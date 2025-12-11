#!/usr/bin/env python3
import socket
import threading
import os
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ---- Crypto utilities ----
def generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key
def compute_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)
def derive_session_key(shared_secret, info=b'chat handshake', length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)
def aesgcm_encrypt(key, plaintext):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext
def aesgcm_decrypt(key, data):
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
# ---- Framing helpers ----
def send_framed(conn, data_bytes):
    length_prefix = len(data_bytes).to_bytes(4, 'big')
    conn.sendall(length_prefix + data_bytes)

def recv_framed(conn):
    length_bytes = recv_exact(conn, 4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    return recv_exact(conn, length)
def recv_exact(conn, count):
    buf = b''
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
# ---- Per-client handler ----
def handle_client_connection(client_socket, client_address):
    print(f"Client connected: {client_address}")
    try:
        # Server generates keypair and sends public key (32 bytes)
        server_private, server_public = generate_keypair()
        server_public_bytes = server_public.public_bytes()
        client_socket.sendall(server_public_bytes)
        # Receive client public key (expect 32 bytes)
        client_public_bytes = recv_exact(client_socket, 32)
        if not client_public_bytes:
            print("Failed to receive client public key.")
            client_socket.close()
            return
        client_public = x25519.X25519PublicKey.from_public_bytes(client_public_bytes)
        # Derive shared session key
        shared = compute_shared_secret(server_private, client_public)
        session_key = derive_session_key(shared)
        # Start send and receive threads
        stop_event = threading.Event()
        def receive_loop():
            try:
                while not stop_event.is_set():
                    framed = recv_framed(client_socket)
                    if framed is None:
                        break
                    try:
                        plaintext = aesgcm_decrypt(session_key, framed)
                    except Exception as e:
                        print("Decryption failed:", e)
                        break
                    print(f"[Client {client_address}] {plaintext.decode(errors='replace')}")
            finally:
                stop_event.set()
        def send_loop():
            try:
                while not stop_event.is_set():
                    try:
                        message = input("Reply to client (empty to quit): ")
                    except (EOFError, KeyboardInterrupt):
                        message = ''
                    if message == '':
                        stop_event.set()
                        break
                    encrypted = aesgcm_encrypt(session_key, message.encode())
                    send_framed(client_socket, encrypted)
            finally:
                stop_event.set()
        recv_thread = threading.Thread(target=receive_loop, daemon=True)
        send_thread = threading.Thread(target=send_loop, daemon=True)
        recv_thread.start()
        send_thread.start()
        # Wait until either thread requests stop
        while not stop_event.is_set():
            stop_event.wait(0.1)
    except Exception as exc:
        print("Connection handler error:", exc)
    finally:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        client_socket.close()
        print(f"Connection closed: {client_address}")
# ---- Server main ----
def run_server(listen_host, listen_port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(5)
    print(f"Server listening on {listen_host}:{listen_port}")
    try:
        while True:
            client_sock, client_addr = srv.accept()
            handler_thread = threading.Thread(
                target=handle_client_connection,
                args=(client_sock, client_addr),
                daemon=True
            )
            handler_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        srv.close()
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python secure_server.py <listen_ip> <listen_port>")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    run_server(host, port)






#!/usr/bin/env python3
import socket
import threading
import os
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ---- Crypto utilities ----
def generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key
def compute_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)
def derive_session_key(shared_secret, info=b'chat handshake', length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)
def aesgcm_encrypt(key, plaintext):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext
def aesgcm_decrypt(key, data):
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
# ---- Framing helpers ----
def send_framed(conn, data_bytes):
    length_prefix = len(data_bytes).to_bytes(4, 'big')
    conn.sendall(length_prefix + data_bytes)
def recv_framed(conn):
    length_bytes = recv_exact(conn, 4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, 'big')
    return recv_exact(conn, length)
def recv_exact(conn, count):
    buf = b''
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
# ---- Client session ----
def run_client(server_host, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_host, server_port))
    try:
        # Receive server public key (32 bytes)
        server_public_bytes = recv_exact(sock, 32)
        if not server_public_bytes:
            print("Failed to receive server public key.")
            return
        server_public = x25519.X25519PublicKey.from_public_bytes(server_public_bytes)
        # Generate client keypair and send public key
        client_private, client_public = generate_keypair()
        client_public_bytes = client_public.public_bytes()
        sock.sendall(client_public_bytes)
        # Derive shared session key
        shared = compute_shared_secret(client_private, server_public)
        session_key = derive_session_key(shared)
        stop_event = threading.Event()
        def receive_loop():
            try:
                while not stop_event.is_set():
                    framed = recv_framed(sock)
                    if framed is None:
                        break
                    try:
                        plaintext = aesgcm_decrypt(session_key, framed)
                    except Exception as e:
                        print("Decryption failed:", e)
                        break
                    print(f"[Server] {plaintext.decode(errors='replace')}")
            finally:
                stop_event.set()
        def send_loop():
            try:
                while not stop_event.is_set():
                    try:
                        message = input("Message to server (empty to quit): ")
                    except (EOFError, KeyboardInterrupt):
                        message = ''
                    if message == '':
                        stop_event.set()
                        break
                    encrypted = aesgcm_encrypt(session_key, message.encode())
                    send_framed(sock, encrypted)
            finally:
                stop_event.set()
        recv_thread = threading.Thread(target=receive_loop, daemon=True)
        send_thread = threading.Thread(target=send_loop, daemon=True)
        recv_thread.start()
        send_thread.start()
        while not stop_event.is_set():
            stop_event.wait(0.1)
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python secure_client.py <server_ip> <server_port>")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    run_client(host, port)
