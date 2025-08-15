import socket
import threading
import time
import os
import struct
import socks  # PySocks
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Configuration ----
RUN_AS_SERVER = True
HOST = '0.0.0.0' if RUN_AS_SERVER else '127.0.0.1'
PORT = 1080

# ---- Thread-safe printing ----
print_lock = threading.Lock()
def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

# ---- Key derivation with salt ----
def derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'handshake data'
    )
    return hkdf.derive(shared_secret)

# ---- Proxy setup ----
def make_socket():
    use_proxy = input("Use SOCKS5 proxy? (y/N): ").strip().lower() == 'y'
    if use_proxy:
        ph = input("Proxy host: ").strip()
        pp = int(input("Proxy port: ").strip())
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, ph, pp)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s

# ---- Graceful shutdown event ----
shutdown_evt = threading.Event()

# ---- Send loop ----
def send_loop(conn: socket.socket, aesgcm: AESGCM):
    seq = 0
    while not shutdown_evt.is_set():
        try:
            line = input()
            if line.lower() in ('/quit', '/exit'):
                shutdown_evt.set()
                conn.close()
                break
            ts = time.time()
            payload = struct.pack('>Iq', seq, int(ts * 1000)) + line.encode()
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, payload, None)
            packet = struct.pack('>I', len(nonce+ct)) + nonce + ct
            conn.sendall(packet)
            seq += 1
        except Exception as e:
            safe_print("Send error:", e)
            shutdown_evt.set()
            break

# ---- Receive loop with replay protection ----
def receive_loop(conn: socket.socket, aesgcm: AESGCM):
    expected_seq = 0
    while not shutdown_evt.is_set():
        try:
            hdr = conn.recv(4)
            if not hdr:
                shutdown_evt.set()
                break
            length = struct.unpack('>I', hdr)[0]
            data = b''
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    raise ConnectionError("Connection closed")
                data += chunk
            nonce, ct = data[:12], data[12:]
            pt = aesgcm.decrypt(nonce, ct, None)
            seq, ts_ms = struct.unpack('>Iq', pt[:12])
            text = pt[12:].decode()
            if seq != expected_seq:
                safe_print(f"Warning: unexpected seq {seq}, expected {expected_seq}")
                expected_seq = seq + 1
            else:
                expected_seq += 1
            tstr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_ms/1000))
            safe_print(f"[{tstr}] Peer:", text)
        except Exception as e:
            safe_print("Receive error:", e)
            shutdown_evt.set()
            break

# ---- Handshake with salt exchange ----
def do_handshake(conn: socket.socket, private_key: x25519.X25519PrivateKey):
    # generate salt
    salt = os.urandom(16)
    # serialize own public key
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    if RUN_AS_SERVER:
        # send salt + pub
        conn.sendall(salt + pub_bytes)
        resp = conn.recv(16 + 32)
        peer_salt, peer_pub = resp[:16], resp[16:]
    else:
        # recv salt + pub
        data = conn.recv(16 + 32)
        peer_salt, peer_pub = data[:16], data[16:]
        # send own
        conn.sendall(salt + pub_bytes)
    # combine salts
    hkdf_salt = bytes(a ^ b for a, b in zip(salt, peer_salt))
    shared = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub))
    key = derive_aes_key(shared, hkdf_salt)
    safe_print("Handshake complete. Secure channel established.")
    return AESGCM(key)

# ---- Main ----
def main():
    sock = make_socket()
    if RUN_AS_SERVER:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(1)
        safe_print(f"Listening on {HOST}:{PORT}")
        conn, addr = sock.accept()
        safe_print("Client connected from", addr)
    else:
        sock.connect((HOST, PORT))
        conn = sock
        safe_print(f"Connected to server at {HOST}:{PORT}")

    priv = x25519.X25519PrivateKey.generate()
    aesgcm = do_handshake(conn, priv)

    t_send = threading.Thread(target=send_loop, args=(conn, aesgcm), daemon=True)
    t_recv = threading.Thread(target=receive_loop, args=(conn, aesgcm), daemon=True)
    t_send.start()
    t_recv.start()
    t_send.join()
    t_recv.join()
    conn.close()

if __name__ == "__main__":
    main()
