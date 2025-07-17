import socket
import threading
import time
import struct
import sys
import select
import logging
from queue import Queue, Empty
from typing import Optional, Dict

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# ---- Configuration ----
HOST = '127.0.0.1'
PORT = 65432

RETRY_INTERVAL = 3          # Client reconnect interval (seconds)
ACK_WAIT_TIMEOUT = 1.5      # Seconds to wait for an ACK
MAX_SEND_RETRIES = 5        # Max resend attempts before giving up
HEARTBEAT_INTERVAL = 10     # Heartbeat send interval (seconds)
HEARTBEAT_TIMEOUT = 30      # Heartbeat timeout (seconds)

# ---- Global State ----
client_socket: Optional[socket.socket] = None
aesgcm: Optional[AESGCM] = None
is_server: bool = False

send_lock = threading.Lock()
packet_lock = threading.Lock()
ack_lock = threading.Lock()
last_recv_lock = threading.Lock()
id_lock = threading.Lock()

running_event = threading.Event()
last_recv_time: float = 0.0
current_packet_id: int = 0
highest_ack_id: int = 0

# Data structure for un-ACKed packets
# packet_store[packet_id] = {
#     "data": bytes, "last_sent": float, "attempts": int, "acked": bool
# }
packet_store: Dict[int, Dict[str, object]] = {}

# Queue of packet_ids to be (re)sent by sender_daemon
send_queue: Queue = Queue()

# Event to signal arrival of an ACK
ack_event = threading.Event()

# ---- Logging Setup ----
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s %(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# ---- Helper Functions ----

def recv_all(sock: socket.socket, length: int) -> bytes:
    """Receive exactly `length` bytes or raise ConnectionError."""
    buffer = b''
    while len(buffer) < length:
        try:
            chunk = sock.recv(length - len(buffer))
        except socket.timeout:
            continue
        if not chunk:
            raise ConnectionError("Socket closed by peer")
        buffer += chunk
    return buffer


def encrypt_message(aes: AESGCM, plaintext: bytes) -> bytes:
    """Encrypt with AESGCM. Returns nonce(12) | ct_length(4) | ciphertext."""
    nonce = AESGCM.generate_nonce()
    ciphertext = aes.encrypt(nonce, plaintext, None)
    length_bytes = len(ciphertext).to_bytes(4, 'big')
    return nonce + length_bytes + ciphertext


def decrypt_message(aes: AESGCM, blob: bytes) -> bytes:
    """Split blob and decrypt. Expects at least 16 bytes (nonce+len)."""
    if len(blob) < 16:
        raise ValueError("Encrypted blob too short")
    nonce = blob[:12]
    length = int.from_bytes(blob[12:16], 'big')
    ct = blob[16:16 + length]
    return aes.decrypt(nonce, ct, None)


def send_raw(data: bytes) -> None:
    """Send raw bytes under send_lock."""
    with send_lock:
        if client_socket is None:
            raise ConnectionError("Socket not connected")
        client_socket.sendall(data)


def send_encrypted(data: bytes) -> None:
    """Encrypt then send."""
    assert aesgcm is not None, "AESGCM not initialized"
    blob = encrypt_message(aesgcm, data)
    send_raw(blob)


def recv_encrypted() -> bytes:
    """Receive and decrypt one message."""
    assert client_socket is not None and aesgcm is not None
    hdr = recv_all(client_socket, 12)
    len_bytes = recv_all(client_socket, 4)
    length = int.from_bytes(len_bytes, 'big')
    ct = recv_all(client_socket, length)
    return decrypt_message(aesgcm, hdr + len_bytes + ct)


def send_ack(packet_id: int) -> None:
    """Send an ACK for the given packet_id."""
    msg = b'ACK' + packet_id.to_bytes(4, 'big')
    send_raw(msg)


def recv_ack() -> int:
    """Receive and parse an ACK, return packet_id."""
    assert client_socket is not None
    hdr = recv_all(client_socket, 3)
    if hdr != b'ACK':
        raise ValueError("Invalid ACK header")
    pid_bytes = recv_all(client_socket, 4)
    return int.from_bytes(pid_bytes, 'big')


def build_packet(packet_id: int, text: str) -> bytes:
    """Construct packet_id(4) | timestamp(8) | text."""
    timestamp = struct.pack('!d', time.time())
    text_bytes = text.encode('utf-8')
    return packet_id.to_bytes(4, 'big') + timestamp + text_bytes


def parse_packet(blob: bytes) -> (int, float, str):
    """Parse packet_id, timestamp, text from plaintext blob."""
    if len(blob) < 12:
        raise ValueError("Packet too short")
    pid = int.from_bytes(blob[:4], 'big')
    timestamp = struct.unpack('!d', blob[4:12])[0]
    text = blob[12:].decode('utf-8', errors='replace')
    return pid, timestamp, text

# ---- X25519 + AESGCM Handshake ----

def perform_handshake(sock: socket.socket, server_mode: bool) -> AESGCM:
    """Do X25519 key exchange and return AESGCM(shared_key)."""
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    if server_mode:
        sock.sendall(public_bytes)
        peer_pub = recv_all(sock, 32)
        shared_key = private_key.exchange(
            x25519.X25519PublicKey.from_public_bytes(peer_pub)
        )
    else:
        peer_pub = recv_all(sock, 32)
        sock.sendall(public_bytes)
        shared_key = private_key.exchange(
            x25519.X25519PublicKey.from_public_bytes(peer_pub)
        )

    return AESGCM(shared_key)

# ---- Heartbeat Thread ----

def heartbeat_thread() -> None:
    global last_recv_time
    while running_event.is_set():
        time.sleep(HEARTBEAT_INTERVAL)
        if not running_event.is_set():
            break

        try:
            send_encrypted(b'HEARTBEAT')
            logging.debug("Sent heartbeat")
        except Exception as ex:
            logging.warning(f"Heartbeat send failed: {ex}")
            running_event.clear()
            break

        with last_recv_lock:
            delta = time.time() - last_recv_time
        if delta > HEARTBEAT_TIMEOUT:
            logging.warning("Heartbeat timeout, closing connection")
            running_event.clear()
            break

# ---- Input Thread ----

def input_thread() -> None:
    """Read user input, build packet, enqueue for sending."""
    global current_packet_id
    while running_event.is_set():
        try:
            line = input("You: ").strip()
        except EOFError:
            logging.info("EOF on stdin, stopping input thread")
            running_event.clear()
            break

        if not line:
            continue

        with id_lock:
            current_packet_id += 1
            pid = current_packet_id

        data = build_packet(pid, line)
        with packet_lock:
            packet_store[pid] = {
                "data": data, "last_sent": 0.0,
                "attempts": 0, "acked": False
            }
        send_queue.put(pid)

# ---- Sender Daemon Thread ----

def sender_daemon() -> None:
    """Take packet_ids from queue, send (with retries) until ACKed."""
    while running_event.is_set():
        try:
            pid = send_queue.get(timeout=0.5)
        except Empty:
            continue

        for attempt in range(1, MAX_SEND_RETRIES + 1):
            if not running_event.is_set():
                return

            with packet_lock:
                info = packet_store.get(pid)
                if not info or info["acked"]:
                    break  # already ACKed or removed
                info["attempts"] = attempt
                info["last_sent"] = time.time()
                data = info["data"]

            try:
                send_encrypted(data)
                logging.info(f"Sent packet {pid}, attempt {attempt}")
            except Exception as ex:
                logging.error(f"Failed to send packet {pid}: {ex}")
                running_event.clear()
                return

            # wait for ACK event
            ack_event.clear()
            got = ack_event.wait(timeout=ACK_WAIT_TIMEOUT)

            with ack_lock:
                acked = highest_ack_id >= pid

            if got and acked:
                with packet_lock:
                    packet_store.pop(pid, None)
                logging.info(f"Packet {pid} ACKed")
                break
        else:
            logging.error(f"Packet {pid} failed after {MAX_SEND_RETRIES} attempts")
            with packet_lock:
                packet_store.pop(pid, None)

# ---- Receiver Thread ----

def receiver_thread() -> None:
    global last_recv_time, highest_ack_id
    while running_event.is_set():
        try:
            ready, _, _ = select.select([client_socket], [], [], 1.0)
            if not ready:
                continue

            peek = client_socket.recv(3, socket.MSG_PEEK)
            if not peek:
                raise ConnectionError("Peer closed")

            if peek == b'ACK':
                pid = recv_ack()
                logging.debug(f"Received ACK {pid}")
                with packet_lock:
                    if pid in packet_store:
                        packet_store[pid]["acked"] = True
                with ack_lock:
                    highest_ack_id = max(highest_ack_id, pid)
                ack_event.set()
            else:
                plaintext = recv_encrypted()

                now = time.time()
                with last_recv_lock:
                    last_recv_time = now

                # Heartbeat echo
                if plaintext == b'HEARTBEAT':
                    send_ack(0)  # 0 means heartbeat ack
                    logging.debug("Heartbeat received and ACKed")
                    continue

                pid, ts, text = parse_packet(plaintext)
                timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                print(f"\n[{timestr}] Peer: {text}\nYou: ", end='', flush=True)
                send_ack(pid)

        except (ConnectionError, OSError) as ex:
            logging.info(f"Connection closed: {ex}")
            running_event.clear()
            break
        except Exception as ex:
            logging.warning(f"Ignoring recv error: {ex}")
            continue

# ---- Server Main Loop ----

def run_server() -> None:
    global client_socket, aesgcm, last_recv_time
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    logging.info(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            logging.info("Waiting for client...")
            conn, addr = server_sock.accept()
            logging.info(f"Connected by {addr}")
            client_socket = conn

            try:
                aesgcm = perform_handshake(client_socket, server_mode=True)
                logging.info("Handshake complete, secure channel established")
            except Exception as ex:
                logging.error(f"Handshake failed: {ex}")
                conn.close()
                continue

            # Reset state
            with last_recv_lock:
                last_recv_time = time.time()
            with packet_lock:
                packet_store.clear()
            with id_lock:
                global current_packet_id
                current_packet_id = 0
            with ack_lock:
                global highest_ack_id
                highest_ack_id = 0

            running_event.set()

            # Start threads
            threads = [
                threading.Thread(target=receiver_thread,    name="Receiver",    daemon=True),
                threading.Thread(target=input_thread,       name="Input",       daemon=True),
                threading.Thread(target=sender_daemon,      name="SenderDaemon",daemon=True),
                threading.Thread(target=heartbeat_thread,   name="Heartbeat",   daemon=True),
            ]
            for t in threads:
                t.start()

            # Wait until connection ends
            while running_event.is_set():
                time.sleep(0.5)

            logging.info("Cleaning up connection")
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except Exception:
                pass
            client_socket = None
            running_event.clear()

    finally:
        server_sock.close()
        logging.info("Server shut down")

# ---- Client Main Loop ----

def run_client() -> None:
    global client_socket, aesgcm, last_recv_time
    while True:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(5)
            conn.connect((HOST, PORT))
            conn.settimeout(None)
            client_socket = conn

            logging.info("Connected to server, starting handshake")
            aesgcm = perform_handshake(client_socket, server_mode=False)
            logging.info("Handshake complete, secure channel established")
            break

        except Exception as ex:
            logging.warning(f"Connect failed ({ex}), retrying in {RETRY_INTERVAL}s")
            time.sleep(RETRY_INTERVAL)

    with last_recv_lock:
        last_recv_time = time.time()
    with packet_lock:
        packet_store.clear()
    with id_lock:
        global current_packet_id
        current_packet_id = 0
    with ack_lock:
        global highest_ack_id
        highest_ack_id = 0

    running_event.set()

    threads = [
        threading.Thread(target=receiver_thread,    name="Receiver",    daemon=True),
        threading.Thread(target=input_thread,       name="Input",       daemon=True),
        threading.Thread(target=sender_daemon,      name="SenderDaemon",daemon=True),
        threading.Thread(target=heartbeat_thread,   name="Heartbeat",   daemon=True),
    ]
    for t in threads:
        t.start()

    try:
        while running_event.is_set():
            time.sleep(0.5)
    finally:
        logging.info("Closing client socket")
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
        except Exception:
            pass
        running_event.clear()
        logging.info("Client shut down")

# ---- Entry Point ----

def main() -> None:
    choice = ''
    while choice.lower() not in ('s', 'c'):
        choice = input("Select role (s=server, c=client): ").strip()
    if choice.lower() == 's':
        run_server()
    else:
        run_client()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Interrupted by user, exiting...")
        running_event.clear()
        if client_socket:
            try:
                client_socket.close()
            except:
                pass
        sys.exit(0)
