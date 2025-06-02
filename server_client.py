import socket
import threading
import struct
import os
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# -------------------------------------------------------------------------
# General helper functions for sending and receiving data
# -------------------------------------------------------------------------
def send_msg(sock: socket.socket, data: bytes):
    """
    Before sending data, send 4 bytes of length info, followed by the data itself to prevent packet sticking.
    """
    try:
        sock.sendall(struct.pack('!I', len(data)))
        sock.sendall(data)
    except Exception as e:
        print(f"[send_msg] Exception: {e}")
def recvall(sock: socket.socket, n: int):
    """
    Receive n bytes of data, ensuring complete reception. Returns None if insufficient data is received or the connection is closed.
    """
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except Exception as e:
            print(f"[recvall] Exception: {e}")
            return None
    return data

def recv_msg(sock: socket.socket):
    """
    First receive 4 bytes indicating the length, then receive the corresponding bytes as the message.
    """
    try:
        raw_len = recvall(sock, 4)
        if not raw_len:
            return None
        msg_len = struct.unpack('!I', raw_len)[0]
        return recvall(sock, msg_len)
    except Exception as e:
        print(f"[recv_msg] Exception: {e}")
        return None
# -------------------------------------------------------------------------
# AES-GCM encryption / decryption using PyCryptodome
# Data format: nonce (12 bytes) + tag (16 bytes) + ciphertext
# -------------------------------------------------------------------------
def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = get_random_bytes(12)  # GCM recommends a 12 byte random nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext
def aes_gcm_decrypt(key: bytes, data: bytes) -> bytes or None:
    try:
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        print(f"[aes_gcm_decrypt] Authentication failed or data error: {e}")
        return None
    except Exception as e:
        print(f"[aes_gcm_decrypt] Exception: {e}")
        return None
# -------------------------------------------------------------------------
# Generate shared key using X25519 and derive the AES key with HKDF
# -------------------------------------------------------------------------
def derive_aes_key(shared_key: bytes, length=32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'handshake data',
    )
    return hkdf.derive(shared_key)
# -------------------------------------------------------------------------
# Base thread class and implementations for sending/receiving threads, ensuring thread safety and exception handling
# -------------------------------------------------------------------------
class SafeSocketThread(threading.Thread):
    def __init__(self, sock, aes_key, role=""):
        super().__init__()
        self.sock = sock
        self.aes_key = aes_key
        self.role = role
        self.daemon = True
        self.running = True

    def stop(self):
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except:
            pass
class Receiver(SafeSocketThread):
    def run(self):
        while self.running:
            data = recv_msg(self.sock)
            if data is None:
                print(f"[{self.role}] Connection closed or reception failed, exiting receiver thread")
                break
            plaintext = aes_gcm_decrypt(self.aes_key, data)
            if plaintext is not None:
                print(f"[{self.role} Receive]: {plaintext.decode(errors='ignore')}")
        self.stop()
class Sender(SafeSocketThread):
    def run(self):
        while self.running:
            try:
                text = input()
                if text.lower() == "exit":
                    print(f"[{self.role}] User requested exit, closing sender thread")
                    self.stop()
                    break
                encrypted = aes_gcm_encrypt(self.aes_key, text.encode())
                send_msg(self.sock, encrypted)
            except Exception as e:
                print(f"[{self.role} Send Exception: {e}, exiting sender thread")
                self.stop()
                break
# -------------------------------------------------------------------------
# TCP Server Implementation
# -------------------------------------------------------------------------
def server(host='127.0.0.1', port=65432):
    print("[Server] Starting...")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(1)
    print(f"[Server] Listening on {host}:{port}")
    try:
        conn, addr = listener.accept()
        print(f"[Server] Connection established - from {addr}")
        # Generate server's X25519 key pair, first send public key to the client
        server_priv = x25519.X25519PrivateKey.generate()
        server_pub = server_priv.public_key()
        send_msg(conn, server_pub.public_bytes())
        # Receive client's public key
        client_pub_raw = recv_msg(conn)
        if client_pub_raw is None:
            print("[Server] Did not receive client's public key, disconnecting")
            conn.close()
            return
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_raw)
        # Compute shared key and derive AES symmetric key
        shared_key = server_priv.exchange(client_pub)
        aes_key = derive_aes_key(shared_key)
        print("[Server] AES shared key agreement complete")
        # Create sender and receiver threads for asynchronous communication
        receiver = Receiver(conn, aes_key, role="Server")
        sender = Sender(conn, aes_key, role="Server")
        receiver.start()
        sender.start()
        receiver.join()  # Wait for the receiver thread to exit
        sender.running = False  # Inform the sender thread to exit (usually terminated by user input "exit")
    except Exception as e:
        print(f"[Server] Exception: {e}")
    finally:
        listener.close()
        print("[Server] Closed")
# -------------------------------------------------------------------------
# TCP Client Implementation
# -------------------------------------------------------------------------
def client(host='127.0.0.1', port=65432):
    print("[Client] Starting...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print("[Client] Connected to server successfully")
        # Receive server's public key
        server_pub_raw = recv_msg(sock)
        if server_pub_raw is None:
            print("[Client] Did not receive server's public key, closing connection")
            sock.close()
            return
        server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_raw)
        # Generate client's X25519 key pair and send public key
        client_priv = x25519.X25519PrivateKey.generate()
        client_pub = client_priv.public_key()
        send_msg(sock, client_pub.public_bytes())
        # Compute shared key and derive AES key
        shared_key = client_priv.exchange(server_pub)
        aes_key = derive_aes_key(shared_key)
        print("[Client] AES shared key agreement complete")
        # Start sender and receiver threads
        receiver = Receiver(sock, aes_key, role="Client")
        sender = Sender(sock, aes_key, role="Client")
        receiver.start()
        sender.start()
        receiver.join()
        sender.running = False
    except Exception as e:
        print(f"[Client] Exception: {e}")
    finally:
        sock.close()
        print("[Client] Connection closed")
# -------------------------------------------------------------------------
# Main entry point, start server or client based on command line parameters
# -------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('server', 'client'):
        print(f"Usage: python {sys.argv[0]} server|client")
        sys.exit(1)

    if sys.argv[1] == 'server':
        server()
    else:
        client()
