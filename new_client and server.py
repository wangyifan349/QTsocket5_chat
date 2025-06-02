#This version has not been fully tested.




server.py

#!/usr/bin/env python3
import socket
import threading
import struct
import os
import json
import time
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
# ------------------------------
# Simple HKDF derivation function for deriving an AES key from the shared secret
# ------------------------------
def hkdf_derive(key_material, salt=b"handshake salt", info=b"AES key"):
    h = HMAC.new(salt, digestmod=SHA256)
    h.update(key_material)
    prk = h.digest()  # pseudorandom key
    h2 = HMAC.new(prk, digestmod=SHA256)
    h2.update(info + b"\x01")
    return h2.digest()  # outputs a 32-byte key
# ------------------------------
# Package data: send 4 bytes of length followed by JSON data
# ------------------------------
def send_packet(conn, data: str):
    encoded = data.encode()
    packet_length = struct.pack(">I", len(encoded))
    conn.sendall(packet_length + encoded)
# ------------------------------
# Receive a complete data packet (first receive 4 bytes of length, then the corresponding data)
# ------------------------------
def recv_packet(conn):
    header = recv_all(conn, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    data = recv_all(conn, length)
    if data is None:
        return None
    return data.decode()

def recv_all(conn, n):
    data = b""
    while len(data) < n:
        try:
            packet = conn.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data += packet
    return data
# ------------------------------
# Global variable: AES key for encryption and decryption
# ------------------------------
aes_key = None
# ------------------------------
# Handshake process: using X25519 for key exchange and HKDF for AES key derivation
# ------------------------------
def handshake(conn, is_server=True):
    global aes_key
    try:
        # Generate X25519 key pair (using PyNaCl)
        my_private = PrivateKey.generate()
        my_public = my_private.public_key
        # Public key exchange process
        if is_server:
            # Server waits for client to send its public key, then sends its own public key
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("Did not receive client's public key")
            peer_pub = json.loads(peer_pub_json)["pub"]
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
        else:
            # Client sends its public key first, then waits for server's reply
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("Did not receive server's public key")
            peer_pub = json.loads(peer_pub_json)["pub"]
        # Convert the peer's public key into a PublicKey object
        peer_public = PublicKey(bytes.fromhex(peer_pub))
        # Compute shared key
        shared = my_private.exchange(peer_public)
        aes_key = hkdf_derive(shared)
        print("[Handshake Success] Shared AES key:", aes_key.hex())
        return True
    except Exception as e:
        print("[Handshake Exception]:", e)
        return False
# ------------------------------
# Encrypt a message and return a JSON formatted string
# The JSON includes nonce, tag, and ciphertext (all converted to hex strings)
# ------------------------------
def encrypt_message(plaintext: bytes) -> str:
    # Generate a random nonce (12 bytes) for AES-GCM
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = {
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    return json.dumps(payload)
# ------------------------------
# Decrypt JSON formatted data and return plaintext bytes
# ------------------------------
def decrypt_message(json_data: str) -> bytes:
    try:
        data = json.loads(json_data)
        nonce = bytes.fromhex(data["nonce"])
        tag = bytes.fromhex(data["tag"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError, CryptoError) as e:
        raise ValueError("Decryption or data format error: " + str(e))
# ------------------------------
# Sending thread: continuously reads user input, encrypts it, and sends it
# ------------------------------
def send_thread(conn):
    while True:
        try:
            msg = input()
            if not msg:
                continue
            # Encrypt the message
            encrypted_json = encrypt_message(msg.encode())
            send_packet(conn, encrypted_json)
        except Exception as e:
            print("[Send Exception]:", e)
            break
# ------------------------------
# Receiving thread: continuously receives data packets, decrypts them, and prints messages
# ------------------------------
def recv_thread(conn):
    while True:
        try:
            data_json = recv_packet(conn)
            if data_json is None:
                print("[Connection closed] Attempting to reconnect...")
                break
            plaintext = decrypt_message(data_json)
            print("\n[Received]:", plaintext.decode())
        except (ValueError, CryptoError) as e:
            print("[Decryption Error]:", e)
        except Exception as e:
            print("[Receive Exception]:", e)
            break
# ------------------------------
# Main function: listen for connections, and reconnect (performing handshake) if disconnected
# ------------------------------
def main():
    host = "0.0.0.0"
    port = 9999
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    print("[Server Started] Waiting for connections...")
    while True:
        try:
            conn, addr = server_sock.accept()
            print("[Connection Established] From:", addr)
            if not handshake(conn, is_server=True):
                conn.close()
                continue
            # Start both sending and receiving threads
            t_send = threading.Thread(target=send_thread, args=(conn,))
            t_recv = threading.Thread(target=recv_thread, args=(conn,))
            t_send.start()
            t_recv.start()
            t_send.join()
            t_recv.join()
            print("[Session Ended] Connection closed, waiting for reconnection...")
            conn.close()
        except Exception as e:
            print("[Main Loop Exception]:", e)
        # Wait a bit before trying for a new connection
        time.sleep(2)
if __name__ == "__main__":
    main()






client.py


#!/usr/bin/env python3
import socket
import threading
import struct
import os
import json
import time
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
# ------------------------------
# Use HKDF to derive the AES key from key material
# ------------------------------
def hkdf_derive(key_material, salt=b"handshake salt", info=b"AES key"):
    h = HMAC.new(salt, digestmod=SHA256)
    h.update(key_material)
    prk = h.digest()
    h2 = HMAC.new(prk, digestmod=SHA256)
    h2.update(info + b"\x01")
    return h2.digest()
# ------------------------------
# Package data: send 4 bytes of length followed by JSON data
# ------------------------------
def send_packet(conn, data: str):
    encoded = data.encode()
    packet_length = struct.pack(">I", len(encoded))
    conn.sendall(packet_length + encoded)
# ------------------------------
# Receive a data packet (first receive length, then JSON data)
# ------------------------------
def recv_packet(conn):
    header = recv_all(conn, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    data = recv_all(conn, length)
    if data is None:
        return None
    return data.decode()

def recv_all(conn, n):
    data = b""
    while len(data) < n:
        try:
            packet = conn.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data += packet
    return data
# ------------------------------
# Global variable: AES key
# ------------------------------
aes_key = None
# ------------------------------
# Handshake process: use X25519 for key exchange and derive the AES key
# ------------------------------
def handshake(conn, is_server=False):
    global aes_key
    try:
        my_private = PrivateKey.generate()
        my_public = my_private.public_key
        if is_server:
            # Server mode
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("Did not receive peer's public key")
            peer_pub = json.loads(peer_pub_json)["pub"]
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
        else:
            # Client mode: send public key first and then wait for reply
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("Did not receive peer's public key")
            peer_pub = json.loads(peer_pub_json)["pub"]
        peer_public = PublicKey(bytes.fromhex(peer_pub))
        shared = my_private.exchange(peer_public)
        aes_key = hkdf_derive(shared)
        print("[Handshake Success] Shared AES key:", aes_key.hex())
        return True
    except Exception as e:
        print("[Handshake Exception]:", e)
        return False
# ------------------------------
# Encrypt a message: use AES-GCM and then construct a JSON object (nonce, tag, ciphertext as hex strings)
# ------------------------------
def encrypt_message(plaintext: bytes) -> str:
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = {
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    return json.dumps(payload)
# ------------------------------
# Decrypt function: parse the JSON formatted message and decrypt it
# ------------------------------
def decrypt_message(json_data: str) -> bytes:
    try:
        data = json.loads(json_data)
        nonce = bytes.fromhex(data["nonce"])
        tag = bytes.fromhex(data["tag"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError, CryptoError) as e:
        raise ValueError("Decryption or data format error: " + str(e))
# ------------------------------
# Sending thread: continuously wait for user input; exit thread upon network error
# ------------------------------
def send_thread(conn):
    while True:
        try:
            msg = input()
            if not msg:
                continue
            encrypted_json = encrypt_message(msg.encode())
            send_packet(conn, encrypted_json)
        except Exception as e:
            print("[Send Exception]:", e)
            break
# ------------------------------
# Receiving thread: continuously receive data; exit on exception
# ------------------------------
def recv_thread(conn):
    while True:
        try:
            data_json = recv_packet(conn)
            if data_json is None:
                print("[Connection closed] Attempting to reconnect...")
                break
            plaintext = decrypt_message(data_json)
            print("\n[Received]:", plaintext.decode())
        except (ValueError, CryptoError) as e:
            print("[Decryption Error]:", e)
        except Exception as e:
            print("[Receive Exception]:", e)
            break
# ------------------------------
# Main client loop: establish connection and automatically reconnect if disconnected
# ------------------------------
def main():
    host = "127.0.0.1"  # Change to the server address if needed
    port = 9999
    while True:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("[Connecting] Attempting to connect to {}:{}".format(host, port))
            conn.connect((host, port))
            print("[Connected] Established connection with the server")
            if not handshake(conn, is_server=False):
                conn.close()
                time.sleep(2)
                continue
            # Start sending and receiving threads
            t_send = threading.Thread(target=send_thread, args=(conn,))
            t_recv = threading.Thread(target=recv_thread, args=(conn,))
            t_send.start()
            t_recv.start()
            t_send.join()
            t_recv.join()
            conn.close()
            print("[Session Ended] Connection closed, waiting for reconnection...")
        except Exception as e:
            print("[Connection Exception]:", e)
        # Wait before reconnecting after disconnection
        time.sleep(2)
if __name__ == "__main__":
    main()

