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
RETRY_INTERVAL = 3
ACK_WAIT_TIMEOUT = 1.5
MAX_SEND_RETRIES = 5
HEARTBEAT_INTERVAL = 10
HEARTBEAT_TIMEOUT = 30

# ---- Logging Setup ----
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s %(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# ---- Connection context ----

class ConnContext:
    def __init__(self):
        self.client_socket: Optional[socket.socket] = None
        self.aesgcm: Optional[AESGCM] = None
        self.running_event = threading.Event()

        # State vars protected by respective locks
        self.packet_store: Dict[int, Dict] = {}
        self.current_packet_id = 0
        self.highest_ack_id = 0
        self.last_recv_time = time.time()

        # Locks
        self.send_lock = threading.Lock()
        self.packet_lock = threading.Lock()
        self.ack_lock = threading.Lock()
        self.last_recv_lock = threading.Lock()
        self.id_lock = threading.Lock()

        self.send_queue = Queue()
        self.ack_event = threading.Event()

# ---- Utility Functions ----

def recv_all(sock: socket.socket, length: int) -> bytes:
    buf = b''
    while len(buf) < length:
        try:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed by peer")
            buf += chunk
        except socket.timeout:
            continue
    return buf

def send_msg(sock: socket.socket, data: bytes, send_lock: threading.Lock) -> None:
    # 4字节长度 + data
    with send_lock:
        total_len = len(data)
        sock.sendall(total_len.to_bytes(4, 'big') + data)

def recv_msg(sock: socket.socket) -> bytes:
    raw_len = recv_all(sock, 4)
    if not raw_len:
        raise ConnectionError("Disconnected")
    length = int.from_bytes(raw_len, 'big')
    data = recv_all(sock, length)
    return data

def encrypt_message(aes: AESGCM, plaintext: bytes) -> bytes:
    nonce = AESGCM.generate_nonce()
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # 12 + len(ciphertext)

def decrypt_message(aes: AESGCM, blob: bytes) -> bytes:
    if len(blob) < 12:
        raise ValueError("Encrypted blob too short")
    nonce = blob[:12]
    ciphertext = blob[12:]
    return aes.decrypt(nonce, ciphertext, None)

# ---- Packet building and parsing ----

def build_packet(packet_id: int, text: str) -> bytes:
    timestamp = struct.pack('!d', time.time())
    text_bytes = text.encode('utf-8')
    return packet_id.to_bytes(4, 'big') + timestamp + text_bytes

def parse_packet(blob: bytes) -> (int, float, str):
    if len(blob) < 12:
        raise ValueError("Packet too short")
    pid = int.from_bytes(blob[:4], 'big')
    timestamp = struct.unpack('!d', blob[4:12])[0]
    text = blob[12:].decode('utf-8', errors='replace')
    return pid, timestamp, text

# ---- Handshake ----

def perform_handshake(sock: socket.socket, server_mode: bool) -> AESGCM:
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    if server_mode:
        sock.sendall(public_bytes)
        peer_pub = recv_all(sock, 32)
    else:
        peer_pub = recv_all(sock, 32)
        sock.sendall(public_bytes)

    shared_key = private_key.exchange(
        x25519.X25519PublicKey.from_public_bytes(peer_pub)
    )
    return AESGCM(shared_key)

# ---- Sending and Receiving Encrypted Messages ----

def send_encrypted(ctx: ConnContext, plaintext: bytes) -> None:
    assert ctx.aesgcm is not None and ctx.client_socket is not None
    blob = encrypt_message(ctx.aesgcm, plaintext)
    send_msg(ctx.client_socket, blob, ctx.send_lock)

def recv_encrypted(ctx: ConnContext) -> bytes:
    assert ctx.client_socket is not None and ctx.aesgcm is not None
    blob = recv_msg(ctx.client_socket)
    return decrypt_message(ctx.aesgcm, blob)

# ---- ACK send/recv functions ----

def send_ack(ctx: ConnContext, packet_id: int) -> None:
    '''
    定义ACK包格式: 第1字节类型=0x02 + 4字节packet_id
    '''
    msg = bytes([0x02]) + packet_id.to_bytes(4, 'big')
    send_msg(ctx.client_socket, msg, ctx.send_lock)

def parse_ack(data: bytes) -> int:
    '''
    ACK包必须5字节 ：1字节类型(0x02)+4字节packet_id
    '''
    if len(data) != 5 or data[0] != 0x02:
        raise ValueError("Invalid ACK format")
    return int.from_bytes(data[1:], 'big')

# ---- Heartbeat send/recv ----

HEARTBEAT_TYPE = 0x03
DATA_TYPE = 0x01

def build_heartbeat() -> bytes:
    # Type byte only, no payload
    return bytes([HEARTBEAT_TYPE])

def parse_heartbeat(data: bytes) -> bool:
    return len(data) == 1 and data[0] == HEARTBEAT_TYPE

def send_heartbeat(ctx: ConnContext) -> None:
    send_msg(ctx.client_socket, build_heartbeat(), ctx.send_lock)

# ---- Thread Functions ----

def receiver_thread(ctx: ConnContext) -> None:
    while ctx.running_event.is_set():
        try:
            ready, _, _ = select.select([ctx.client_socket], [], [], 1.0)
            if not ready:
                continue

            data = recv_msg(ctx.client_socket)
            if not data:
                raise ConnectionError("Peer closed")

            # 根据首字节区分消息类型
            mtype = data[0]

            # 更新最后接收时间
            now = time.time()
            with ctx.last_recv_lock:
                ctx.last_recv_time = now

            if mtype == 0x02:  # ACK包
                pid = parse_ack(data)
                logging.debug(f"Received ACK {pid}")
                with ctx.packet_lock:
                    if pid in ctx.packet_store:
                        ctx.packet_store[pid]['acked'] = True
                with ctx.ack_lock:
                    ctx.highest_ack_id = max(ctx.highest_ack_id, pid)
                ctx.ack_event.set()

            elif mtype == HEARTBEAT_TYPE:
                # 远端心跳，回复ACK 0
                send_ack(ctx, 0)
                logging.debug("Heartbeat received and ACKed")

            elif mtype == DATA_TYPE:
                # AES加密数据在data[1:]
                plaintext = ctx.aesgcm.decrypt(data[1:13], data[13:], None) if False else None  # 之前是nonce + ciphertext
                # 这里改成解密整个data[1:]因为是加密blob
                # 但因为我们现在的加密blob是完整发送的，消息首字节标识和加密数据分开
                # 为保持一致，重写为：

                ciphertext_blob = data[1:]
                plaintext = decrypt_message(ctx.aesgcm, ciphertext_blob)

                pid, ts, text = parse_packet(plaintext)
                timestr = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                print(f"\n[{timestr}] Peer: {text}\nYou: ", end='', flush=True)
                # 回复ACK
                send_ack(ctx, pid)
            else:
                logging.warning(f"Unknown message type {mtype}, ignoring")

        except (ConnectionError, OSError) as ex:
            logging.info(f"Connection closed: {ex}")
            ctx.running_event.clear()
            break
        except Exception as ex:
            logging.warning(f"Ignoring recv error: {ex}")
            continue

def input_thread(ctx: ConnContext) -> None:
    while ctx.running_event.is_set():
        try:
            line = input("You: ").strip()
        except EOFError:
            logging.info("EOF on stdin, stopping input thread")
            ctx.running_event.clear()
            break

        if not line:
            continue

        with ctx.id_lock:
            ctx.current_packet_id += 1
            pid = ctx.current_packet_id

        data = build_packet(pid, line)
        # 数据包格式：类型(1byte) + 加密数据
        # 先加密，再加类型标识byte
        packet_encrypted = encrypt_message(ctx.aesgcm, data)

        to_send = bytes([DATA_TYPE]) + packet_encrypted

        with ctx.packet_lock:
            ctx.packet_store[pid] = {
                "data": to_send,
                "last_sent": 0.0,
                "attempts": 0,
                "acked": False
            }
        ctx.send_queue.put(pid)

def sender_daemon(ctx: ConnContext) -> None:
    while ctx.running_event.is_set():
        try:
            pid = ctx.send_queue.get(timeout=0.5)
        except Empty:
            continue

        for attempt in range(1, MAX_SEND_RETRIES + 1):
            if not ctx.running_event.is_set():
                return

            with ctx.packet_lock:
                info = ctx.packet_store.get(pid)
                if not info or info['acked']:
                    break
                info['attempts'] = attempt
                info['last_sent'] = time.time()
                data = info['data']

            try:
                send_msg(ctx.client_socket, data, ctx.send_lock)
                logging.info(f"Sent packet {pid}, attempt {attempt}")
            except Exception as ex:
                logging.error(f"Failed to send packet {pid}: {ex}")
                ctx.running_event.clear()
                return

            ctx.ack_event.clear()
            got_ack = ctx.ack_event.wait(ACK_WAIT_TIMEOUT)

            with ctx.ack_lock:
                acked = ctx.highest_ack_id >= pid

            if got_ack and acked:
                with ctx.packet_lock:
                    ctx.packet_store.pop(pid, None)
                logging.info(f"Packet {pid} ACKed")
                break
        else:
            logging.error(f"Packet {pid} failed after {MAX_SEND_RETRIES} attempts")
            with ctx.packet_lock:
                ctx.packet_store.pop(pid, None)

def heartbeat_thread(ctx: ConnContext) -> None:
    while ctx.running_event.is_set():
        time.sleep(HEARTBEAT_INTERVAL)
        if not ctx.running_event.is_set():
            break

        try:
            send_heartbeat(ctx)
            logging.debug("Sent heartbeat")
        except Exception as ex:
            logging.warning(f"Heartbeat send failed: {ex}")
            ctx.running_event.clear()
            break

        with ctx.last_recv_lock:
            delta = time.time() - ctx.last_recv_time
        if delta > HEARTBEAT_TIMEOUT:
            logging.warning("Heartbeat timeout, closing connection")
            ctx.running_event.clear()
            break

# ---- Server/Client common function to start workers ----

def start_threads(ctx: ConnContext):
    threads = [
        threading.Thread(target=receiver_thread, args=(ctx,), name="Receiver", daemon=True),
        threading.Thread(target=input_thread, args=(ctx,), name="Input", daemon=True),
        threading.Thread(target=sender_daemon, args=(ctx,), name="SenderDaemon", daemon=True),
        threading.Thread(target=heartbeat_thread, args=(ctx,), name="Heartbeat", daemon=True)
    ]
    for t in threads:
        t.start()
    return threads

# ---- Run Server ----

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        logging.info(f"Server listening on {HOST}:{PORT}")

        while True:
            logging.info("Waiting for client...")
            try:
                conn, addr = server_sock.accept()
            except KeyboardInterrupt:
                logging.info("Server exiting on user interrupt")
                break

            logging.info(f"Connected by {addr}")
            ctx = ConnContext()
            ctx.client_socket = conn

            try:
                ctx.aesgcm = perform_handshake(ctx.client_socket, server_mode=True)
                logging.info("Handshake complete, secure channel established")
            except Exception as ex:
                logging.error(f"Handshake failed: {ex}")
                conn.close()
                continue

            with ctx.last_recv_lock:
                ctx.last_recv_time = time.time()
            with ctx.packet_lock:
                ctx.packet_store.clear()
            with ctx.id_lock:
                ctx.current_packet_id = 0
            with ctx.ack_lock:
                ctx.highest_ack_id = 0

            ctx.running_event.set()

            threads = start_threads(ctx)

            # 等待连接中断
            try:
                while ctx.running_event.is_set():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                logging.info("Server interrupted by user")
                ctx.running_event.clear()

            logging.info("Cleaning up connection")
            try:
                ctx.client_socket.shutdown(socket.SHUT_RDWR)
                ctx.client_socket.close()
            except Exception:
                pass

# ---- Run Client ----

def run_client():
    ctx = ConnContext()

    while True:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(5)
            conn.connect((HOST, PORT))
            conn.settimeout(None)
            ctx.client_socket = conn

            logging.info("Connected to server, starting handshake")
            ctx.aesgcm = perform_handshake(ctx.client_socket, server_mode=False)
            logging.info("Handshake complete, secure channel established")
            break
        except Exception as ex:
            logging.warning(f"Connect failed ({ex}), retrying in {RETRY_INTERVAL}s")
            time.sleep(RETRY_INTERVAL)

    with ctx.last_recv_lock:
        ctx.last_recv_time = time.time()
    with ctx.packet_lock:
        ctx.packet_store.clear()
    with ctx.id_lock:
        ctx.current_packet_id = 0
    with ctx.ack_lock:
        ctx.highest_ack_id = 0

    ctx.running_event.set()

    threads = start_threads(ctx)

    try:
        while ctx.running_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        logging.info("Client interrupted by user")
        ctx.running_event.clear()
    finally:
        logging.info("Closing client socket")
        try:
            ctx.client_socket.shutdown(socket.SHUT_RDWR)
            ctx.client_socket.close()
        except Exception:
            pass

if __name__ == '__main__':
    try:
        choice = ''
        while choice.lower() not in ('s', 'c'):
            choice = input("Select role (s=server, c=client): ").strip()
        if choice.lower() == 's':
            run_server()
        else:
            run_client()
    except KeyboardInterrupt:
        logging.info("Interrupted by user, exiting...")
        sys.exit(0)
