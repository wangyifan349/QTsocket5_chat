import socket                  # low-level BSD socket interface
import threading               # threading support
import time                    # time-related functions
import struct                  # pack/unpack binary data
import sys                     # system-specific parameters and functions
import select                  # wait for I/O completion
import logging                 # logging facility
from queue import Queue, Empty # thread‐safe FIFO queue
from typing import Optional, Dict

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# ---- Configuration ----
HOST = '127.0.0.1'              # listen/connect on localhost
PORT = 65432                    # TCP port for server/client

RETRY_INTERVAL = 3              # seconds between client reconnect attempts
ACK_WAIT_TIMEOUT = 1.5          # seconds to wait for an ACK before retry
MAX_SEND_RETRIES = 5            # max number of resend attempts per packet
HEARTBEAT_INTERVAL = 10         # seconds between heartbeat messages
HEARTBEAT_TIMEOUT = 30          # seconds to consider connection dead

# ---- Global State ----
client_socket: Optional[socket.socket] = None  # active TCP socket
aesgcm: Optional[AESGCM] = None                # AES-GCM cipher instance
is_server: bool = False                        # role flag (unused)

# locks to protect shared state in multi-threaded environment
send_lock = threading.Lock()       # serialize socket.sendall() calls
packet_lock = threading.Lock()     # protect packet_store access
ack_lock = threading.Lock()        # protect highest_ack_id updates
last_recv_lock = threading.Lock()  # protect last_recv_time updates
id_lock = threading.Lock()         # protect current_packet_id increments

running_event = threading.Event()  # flag to signal threads to run/stop
last_recv_time: float = 0.0        # timestamp of last received message
current_packet_id: int = 0         # monotonic counter for outgoing packets
highest_ack_id: int = 0            # highest packet ID acknowledged by peer

# store metadata for un-ACKed packets
# format: packet_store[packet_id] = {
#   "data": bytes,          # raw packet data
#   "last_sent": float,     # last send timestamp
#   "attempts": int,        # how many times we've sent it
#   "acked": bool           # whether we've received an ACK
# }
packet_store: Dict[int, Dict[str, object]] = {}

# queue of packet_ids to send or re-send
send_queue: Queue = Queue()

# Event to wake sender_daemon when an ACK arrives
ack_event = threading.Event()

# ---- Logging Setup ----
logging.basicConfig(
    level=logging.INFO,            # set default log level to INFO
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
            continue  # retry on timeout
        if not chunk:
            raise ConnectionError("Socket closed by peer")
        buffer += chunk
    return buffer

def encrypt_message(aes: AESGCM, plaintext: bytes) -> bytes:
    """Encrypt with AESGCM. Returns nonce(12) | ct_length(4) | ciphertext."""
    nonce = AESGCM.generate_nonce()                   # 12-byte random nonce
    ciphertext = aes.encrypt(nonce, plaintext, None)   # AEAD encrypt
    length_bytes = len(ciphertext).to_bytes(4, 'big')  # 4-byte length prefix
    return nonce + length_bytes + ciphertext

def decrypt_message(aes: AESGCM, blob: bytes) -> bytes:
    """Split blob and decrypt. Expects at least 16 bytes (nonce+len)."""
    if len(blob) < 16:
        raise ValueError("Encrypted blob too short")
    nonce = blob[:12]                                  # extract nonce
    length = int.from_bytes(blob[12:16], 'big')        # extract ciphertext length
    ct = blob[16:16 + length]                          # extract actual ciphertext
    return aes.decrypt(nonce, ct, None)                # return plaintext

def send_raw(data: bytes) -> None:
    """Send raw bytes under send_lock to avoid interleaving."""
    with send_lock:
        if client_socket is None:
            raise ConnectionError("Socket not connected")
        client_socket.sendall(data)

def send_encrypted(data: bytes) -> None:
    """Encrypt data then send as a framed message."""
    assert aesgcm is not None, "AESGCM not initialized"
    blob = encrypt_message(aesgcm, data)
    send_raw(blob)

def recv_encrypted() -> bytes:
    """Receive and decrypt one encrypted message from the socket."""
    assert client_socket is not None and aesgcm is not None
    hdr = recv_all(client_socket, 12)          # nonce
    len_bytes = recv_all(client_socket, 4)     # length of ciphertext
    length = int.from_bytes(len_bytes, 'big')
    ct = recv_all(client_socket, length)       # ciphertext
    return decrypt_message(aesgcm, hdr + len_bytes + ct)

def send_ack(packet_id: int) -> None:
    """Send an ACK header + 4-byte packet_id (network byte order)."""
    msg = b'ACK' + packet_id.to_bytes(4, 'big')
    send_raw(msg)

def recv_ack() -> int:
    """Receive and parse an ACK, return the acknowledged packet_id."""
    assert client_socket is not None
    hdr = recv_all(client_socket, 3)
    if hdr != b'ACK':
        raise ValueError("Invalid ACK header")
    pid_bytes = recv_all(client_socket, 4)
    return int.from_bytes(pid_bytes, 'big')

def build_packet(packet_id: int, text: str) -> bytes:
    """Construct packet_id (4 bytes) | timestamp (8 bytes) | UTF-8 text."""
    timestamp = struct.pack('!d', time.time())   # double float in network order
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
    """
    Do X25519 key exchange and return AESGCM(shared_key).
    Server sends its public key first; client reads then responds.
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    if server_mode:
        sock.sendall(public_bytes)                 # send server pubkey
        peer_pub = recv_all(sock, 32)              # receive client pubkey
    else:
        peer_pub = recv_all(sock, 32)              # receive server pubkey
        sock.sendall(public_bytes)                 # send client pubkey

    shared_key = private_key.exchange(
        x25519.X25519PublicKey.from_public_bytes(peer_pub)
    )
    return AESGCM(shared_key)                       # derive AEAD cipher

# ---- Heartbeat Thread ----

def heartbeat_thread() -> None:
    global last_recv_time
    while running_event.is_set():
        time.sleep(HEARTBEAT_INTERVAL)            # wait between heartbeats
        if not running_event.is_set():
            break

        try:
            send_encrypted(b'HEARTBEAT')           # send encrypted heartbeat
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
    """
    Read user input lines, build a packet with an incrementing ID,
    store it in packet_store, and enqueue its ID for sending.
    """
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

        data = build_packet(pid, line)           # build packet bytes
        with packet_lock:
            packet_store[pid] = {
                "data": data,
                "last_sent": 0.0,
                "attempts": 0,
                "acked": False
            }
        send_queue.put(pid)                      # enqueue for sender_daemon

# ---- Sender Daemon Thread ----

def sender_daemon() -> None:
    """
    Pull packet IDs from send_queue and send them encrypted.
    Wait up to ACK_WAIT_TIMEOUT for an ACK, retry up to MAX_SEND_RETRIES.
    """
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
                    break  # nothing to send or already ACKed
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

            # wait for its ACK
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
            # ran out of retries
            logging.error(f"Packet {pid} failed after {MAX_SEND_RETRIES} attempts")
            with packet_lock:
                packet_store.pop(pid, None)

# ---- Receiver Thread ----

def receiver_thread() -> None:
    """
    Continuously select on the socket. Distinguish between raw ACK frames ("ACK"+id)
    and encrypted messages (which we decrypt). Update last_recv_time on any message.
    """
    global last_recv_time, highest_ack_id

    while running_event.is_set():
        try:
            ready, _, _ = select.select([client_socket], [], [], 1.0)
            if not ready:
                continue

            # peek first few bytes to see if it's an ACK
            peek = client_socket.recv(3, socket.MSG_PEEK)
            if not peek:
                raise ConnectionError("Peer closed")

            if peek == b'ACK':
                pid = recv_ack()                     # consume ACK frame
                logging.debug(f"Received ACK {pid}")
                with packet_lock:
                    if pid in packet_store:
                        packet_store[pid]["acked"] = True
                with ack_lock:
                    highest_ack_id = max(highest_ack_id, pid)
                ack_event.set()                     # notify sender_daemon
            else:
                plaintext = recv_encrypted()        # receive & decrypt message

                now = time.time()
                with last_recv_lock:
                    last_recv_time = now

                # handle heartbeat specially
                if plaintext == b'HEARTBEAT':
                    send_ack(0)                    # ack heartbeat with ID=0
                    logging.debug("Heartbeat received and ACKed")
                    continue

                pid, ts, text = parse_packet(plaintext)
                timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                # print incoming message and re‐prompt user
                print(f"\n[{timestr}] Peer: {text}\nYou: ", end='', flush=True)
                send_ack(pid)                      # ack this packet
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

            # reset shared state for new connection
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

            # spawn threads for I/O, sending, heartbeats
            threads = [
                threading.Thread(target=receiver_thread,    name="Receiver",    daemon=True),
                threading.Thread(target=input_thread,       name="Input",       daemon=True),
                threading.Thread(target=sender_daemon,      name="SenderDaemon",daemon=True),
                threading.Thread(target=heartbeat_thread,   name="Heartbeat",   daemon=True),
            ]
            for t in threads:
                t.start()

            # block until connection tear-down
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

    # retry connecting until successful
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

    # initialize per-connection state
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

    # spawn worker threads
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
