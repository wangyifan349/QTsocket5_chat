import socket
import threading
import struct
import time
import json
import base58
from nacl.public import PrivateKey
from nacl.bindings import crypto_scalarmult
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def recvall(sock, n):
    """Receive exactly n bytes from socket"""
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket connection closed prematurely")
        data += packet
    return data

def send_message(sock, data):
    """Send data prefixed with its length (4 bytes big endian)"""
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)

def recv_message(sock):
    """Receive a length-prefixed message"""
    length_bytes = recvall(sock, 4)
    length = struct.unpack(">I", length_bytes)[0]
    return recvall(sock, length)

def aes_gcm_encrypt(key, plaintext):
    """Encrypt plaintext bytes with AES-GCM using key.
    Returns JSON dict encoded as bytes with base58 nonce, tag, ciphertext"""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    result_dict = {
        "nonce": base58.b58encode(nonce).decode(),       # nonce base58 encoded
        "tag": base58.b58encode(tag).decode(),           # tag base58 encoded
        "ciphertext": base58.b58encode(ciphertext).decode()  # ciphertext base58 encoded
    }
    return json.dumps(result_dict).encode()

def aes_gcm_decrypt(key, data):
    """Decrypt JSON dict (bytes) AES-GCM encrypted message to plaintext bytes"""
    data_dict = json.loads(data.decode())
    nonce = base58.b58decode(data_dict["nonce"])
    tag = base58.b58decode(data_dict["tag"])
    ciphertext = base58.b58decode(data_dict["ciphertext"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def pack_message(timestamp, msg_bytes):
    """Pack Unix timestamp (8 bytes big endian) and message bytes"""
    return struct.pack(">Q", timestamp) + msg_bytes

def unpack_message(packed):
    """Unpack to timestamp and message bytes"""
    timestamp = struct.unpack(">Q", packed[:8])[0]
    msg_bytes = packed[8:]
    return timestamp, msg_bytes

def send_loop(sock, key):
    """Thread function to read user input, encrypt and send"""
    try:
        while True:
            user_input = input("Enter message to send: ").strip()
            if not user_input:
                continue
            timestamp = int(time.time())
            plain = pack_message(timestamp, user_input.encode())  # Pack timestamp + message
            enc = aes_gcm_encrypt(key, plain)                      # Encrypt with AES-GCM
            send_message(sock, enc)                                # Send length-prefixed encrypted message
    except Exception as e:
        print("Send thread error:", e)

def recv_loop(sock, key):
    """Thread function to receive, decrypt and display messages"""
    try:
        while True:
            enc = recv_message(sock)               # Receive encrypted message
            plain = aes_gcm_decrypt(key, enc)     # Decrypt AES-GCM
            timestamp, msg_bytes = unpack_message(plain)  # Extract timestamp and message
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            print(f"\n[{tstr}] Received:", msg_bytes.decode())
    except Exception as e:
        print("Receive thread error:", e)

def run_client(server_host, server_port):
    """Run client mode: connect to server, perform handshake, then chat"""
    priv = PrivateKey.generate()                   # Generate Curve25519 private key
    pub_bytes = bytes(priv.public_key)             # Get public key bytes

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))     # Connect to server
        send_message(s, pub_bytes)                 # Send client's public key
        server_pub_bytes = recv_message(s)         # Receive server's public key
        # Derive shared secret (32 bytes)
        shared_key = crypto_scalarmult(priv._private_key, server_pub_bytes)[:32]

        print("Handshake done. Secure channel established.")

        # Start receive and send threads
        t_recv = threading.Thread(target=recv_loop, args=(s, shared_key), daemon=True)
        t_send = threading.Thread(target=send_loop, args=(s, shared_key), daemon=True)

        t_recv.start()
        t_send.start()

        t_recv.join()
        t_send.join()

def run_server(bind_host, bind_port):
    """Run server mode: listen for client, perform handshake, then chat"""
    priv = PrivateKey.generate()                   # Generate Curve25519 private key
    pub_bytes = bytes(priv.public_key)             # Get public key bytes

    def handle_client(conn, addr):
        try:
            client_pub_bytes = recv_message(conn)  # Receive client's public key
            send_message(conn, pub_bytes)          # Send server's public key
            # Derive shared secret (32 bytes)
            shared_key = crypto_scalarmult(priv._private_key, client_pub_bytes)[:32]

            print(f"Handshake with {addr} done. Secure channel established.")

            # Start receive and send threads
            t_recv = threading.Thread(target=recv_loop, args=(conn, shared_key), daemon=True)
            t_send = threading.Thread(target=send_loop, args=(conn, shared_key), daemon=True)

            t_recv.start()
            t_send.start()

            t_recv.join()
            t_send.join()
        except Exception as e:
            print(f"Connection {addr} error:", e)
        finally:
            conn.close()
            print(f"Connection {addr} closed.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind_host, bind_port))             # Bind to interface and port
        s.listen(1)                                # Listen for one connection
        print(f"Server listening on {bind_host}:{bind_port}")
        while True:
            conn, addr = s.accept()                 # Accept client connection
            print(f"Connected by {addr}")
            # Handle client in separate thread to allow multiple connections if desired
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def main():
    mode = input("Choose mode (server/client): ").strip().lower()
    if mode == "server":
        host = input("Bind host (default 0.0.0.0): ").strip()
        if not host:
            host = "0.0.0.0"
        port_str = input("Bind port (default 12345): ").strip()
        port = int(port_str) if port_str else 12345
        run_server(host, port)
    elif mode == "client":
        host = input("Server IP (default 127.0.0.1): ").strip()
        if not host:
            host = "127.0.0.1"
        port_str = input("Server port (default 12345): ").strip()
        port = int(port_str) if port_str else 12345
        run_client(host, port)
    else:
        print("Invalid mode. Please choose 'server' or 'client'.")

if __name__ == "__main__":
    main()
