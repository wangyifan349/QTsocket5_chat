#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
""" 
secure_transfer.py
=====================================================================
功能说明  Function Description
--------------------------------------------------------------------- 
本脚本演示如何在 单一文件 中实现一个真正可用的安全 TCP 通信。 
所有功能均带【中文 + English】双语注释。 
功能列表  Feature List
1. X25519(ECDH) 用于密钥交换                                     | 
   Use X25519 (Elliptic Curve Diffie–Hellman) to create a             | 
   shared secret between two peers.                                   | 
2. HKDF-SHA256 从共享密钥导出 32 字节会话密钥                      | 
   Derive a 32-byte session key from the shared secret                | 
   using HKDF with SHA-256.                                           | 
3. ChaCha20-Poly1305 (PyCryptodome 实现) 进行加密和完整性校验       | 
   Employ ChaCha20-Poly1305 (from PyCryptodome) for                   | 
   authenticated encryption (confidentiality + integrity).           | 
4. 发送与接收在独立线程，无阻塞                                     | 
   Sending and receiving run on separate threads to avoid blocking.   | 
5. 支持发送普通文本                                                  | 
   Support for sending plain text messages.                           | 
6. 支持大文件（按 64 KiB 分块）并附带 SHA-256 校验                  | 
   Support large file transfer (64 KiB chunks) with SHA-256 checksum. | 
7. 协议、数据帧格式在下方 **Protocol Specification** 中写明          | 
   Protocol and frame formats are documented below.                   | 
=====================================================================
协议规格  Protocol Specification
--------------------------------------------------------------------- 
(1) 端口 Port: 5555 (可在源代码中修改 / configurable in source) 
(2) 握手阶段 Handshake
    • 客户端 -> 服务端: 发送公钥                 | 
      Client  -> Server : send its public key    | 
    • 服务端 -> 客户端: 发送公钥                 | 
      Server  -> Client : send its public key    | 
    • 双方使用 private_key.exchange(peer_pub_key) 计算共享密钥       | 
      Both sides compute shared secret via private.exchange().        | 
    • 使用 HKDF-SHA256(info="SecureTransfer") 派生 32 字节会话密钥    | 
      Derive 32-byte session key via HKDF-SHA256.                     | 
(3) 加密后帧格式 Encrypted Frame
    ┌─────────4 bytes──────────┐  Big-endian uint32 length prefix
    │ length prefix            │  4 字节大端长度前缀
    └──────────────────────────┘
    ┌─────12────┬────16────┬─────────────┐
    │  nonce    │   tag    │ ciphertext  │
    │  随机数    │   标签   │    密文      │
    └───────────┴──────────┴─────────────┘
(4) 解密后明文格式 Plaintext after Decrypt
    ┌ 1 Byte ┬   payload ...                                   ┐
    │ type   │   负载 (按类型解析 / interpreted by type)        │
    └────────┴─────────────────────────────────────────────────┘
    type = 0x01 TEXT        : UTF-8 编码文本 / UTF-8 encoded text
    type = 0x02 FILE_META    : 文件元数据 / file meta information
        payload = | nameLen(2) | size(8) | digest(32) | filename | 
    type = 0x03 FILE_CHUNK   : 文件块 / raw file chunk (≤64 KiB) 
    type = 0x04 CLOSE        : 关闭指令 / connection close signal
(5) 文件校验 File Integrity
    • 发送端计算整文件 SHA-256, 放入 FILE_META.digest              | 
      Sender pre-computes SHA-256 and sends it within FILE_META.     | 
    • 接收端流式计算 SHA-256, 传输完毕后比对                        | 
      Receiver streams SHA-256 and compares when done.              | 
=====================================================================
""" 

# ───────────────────────────────
# 标准库导入  Standard Library Imports
# ───────────────────────────────
import os                                                    # 文件操作 / File IO
import sys                                                   # 命令行参数 / argv
import socket                                                # TCP Socket
import struct                                                # 二进制打包 / pack
import threading                                             # 多线程 / threading
import pathlib                                               # 路径处理 / path
import hashlib                                               # SHA-256
from typing import Optional, Tuple, BinaryIO                 # 类型提示 / typing

# ───────────────────────────────
# 第三方库导入  Third-Party Imports
# ───────────────────────────────
from cryptography.hazmat.primitives.asymmetric.x25519 import ( 
    X25519PrivateKey, X25519PublicKey)                      # X25519 密钥对
from cryptography.hazmat.primitives.kdf.hkdf import HKDF     # HKDF
from cryptography.hazmat.primitives import hashes            # Hash 函数
from cryptography.hazmat.primitives import serialization     # [修正] 序列化支持
from Crypto.Cipher import ChaCha20_Poly1305                  # ChaCha20-Poly1305
# ───────────────────────────────
# 常量定义  Constant Definitions
# ───────────────────────────────
TCP_PORT: int = 5555                         # 默认监听端口 / default port
FILE_CHUNK_SIZE: int = 64 * 1024             # 64 KiB 文件分块 / file chunk
NONCE_SIZE: int = 12                         # ChaCha20 nonce 长度 12 bytes
TAG_SIZE: int = 16                           # ChaCha20 tag 长度 16 bytes
# 消息类型枚举 / Message Type Enum
MSG_TEXT: int = 0x01         # 文本消息 / plain text
MSG_FILE_META: int = 0x02    # 文件元数据 / file meta
MSG_FILE_CHUNK: int = 0x03   # 文件数据块 / file chunk
MSG_CLOSE: int = 0x04        # 关闭连接 / close signal
# ───────────────────────────────
# 工具函数  Utility Functions
# ───────────────────────────────
def send_frame(sock: socket.socket, data: bytes) -> None: 
    """ 
    发送一帧 (4 字节长度前缀 + 数据体) 
    Send one frame (4-byte length prefix + payload). 
    """ 
    sock.sendall(struct.pack('>I', len(data)) + data)        # sendall ensures all bytes sent
def recv_frame(sock: socket.socket) -> bytes: 
    """ 
    阻塞读取一帧；若连接被关闭抛 EOFError。 
    Blocking read a frame; raise EOFError if connection closes. 
    """ 
    length_prefix: bytes = sock.recv(4)                      # 读取 4 字节前缀 / read prefix
    if len(length_prefix) < 4: 
        raise EOFError('connection closed (prefix)')         # 对端关闭 / peer closed
    frame_len: int = struct.unpack('>I', length_prefix)[0]   # 解包 / unpack length
    buffer: bytearray = bytearray() 
    while len(buffer) < frame_len:                           # 循环直到读完 / loop till done
        chunk: bytes = sock.recv(frame_len - len(buffer)) 
        if not chunk: 
            raise EOFError('connection closed (payload)') 
        buffer.extend(chunk) 
    return bytes(buffer) 
def derive_key(shared_secret: bytes) -> bytes: 
    """ 
    使用 HKDF-SHA256 从共享密钥导出对称密钥。 
    Derive symmetric key from shared secret via HKDF-SHA256. 
    """ 
    hkdf = HKDF(algorithm=hashes.SHA256(), 
                length=32, 
                salt=None, 
                info=b'SecureTransfer') 
    return hkdf.derive(shared_secret) 
def encrypt(key: bytes, plaintext: bytes) -> bytes: 
    """ 
    ChaCha20-Poly1305 加密 → 输出 nonce|tag|ciphertext。 
    Encrypt using ChaCha20-Poly1305, return nonce|tag|ciphertext. 
    """ 
    nonce = os.urandom(NONCE_SIZE)                           # 生成随机 nonce / random nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce) 
    ciphertext, tag = cipher.encrypt_and_digest(plaintext) 
    return nonce + tag + ciphertext
def decrypt(key: bytes, packet: bytes) -> bytes: 
    """ 
    解密并校验 ChaCha20-Poly1305 数据包。 
    Decrypt and verify ChaCha20-Poly1305 packet. 
    """ 
    nonce = packet[:NONCE_SIZE] 
    tag = packet[NONCE_SIZE:NONCE_SIZE + TAG_SIZE] 
    ciphertext = packet[NONCE_SIZE + TAG_SIZE:] 
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce) 
    return cipher.decrypt_and_verify(ciphertext, tag) 
# ───────────────────────────────
# SecureConnection 类
# ───────────────────────────────
class SecureConnection: 
    """ 
    表示一条完成握手后的安全连接。 
    Represent a secure TCP connection after handshake is done. 
    """ 
    def __init__(self, sock: socket.socket, key: bytes) -> None: 
        self.sock: socket.socket = sock                               # TCP 套接字
        self.key: bytes = key                                         # 会话对称密钥
        self.alive: bool = True                                       # 连接存活标志
        self.send_lock = threading.Lock()                             # 发送线程锁
        # 正在接收的文件状态: 
        # (目标文件名, 总大小, 已接收字节, 文件句柄, 哈希对象, 期望 digest) 
        self.incoming_file: Optional[ 
            Tuple[str, int, int, BinaryIO, hashlib._Hash, bytes] 
        ] = None
        # 启动接收线程  Start receive thread
        self.recv_thread = threading.Thread(target=self._recv_loop, 
                                            daemon=True) 
        self.recv_thread.start() 
    # ---------------- 公开 API  Public Interface ---------------- # 
    def send_text(self, text: str) -> None: 
        """发送文本消息  Send plain text""" 
        self._send(MSG_TEXT, text.encode()) 
    def send_file(self, path: str) -> None: 
        """发送文件（分块 + SHA-256 校验）Send a file with chunking + SHA-256""" 
        path_obj = pathlib.Path(path) 
        if not path_obj.is_file(): 
            print(f'!! File not found: {path}') 
            return
        file_size = path_obj.stat().st_size
        file_name_bytes = path_obj.name.encode() 
        # 计算完整 SHA-256  Compute SHA-256 in advance
        sha256 = hashlib.sha256() 
        with path_obj.open('rb') as f: 
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''): 
                sha256.update(chunk) 
        digest = sha256.digest()                                      # 32 字节
        # 发送 FILE_META  Send FILE_META
        meta_payload = ( 
            struct.pack('>H', len(file_name_bytes)) +                 # 文件名长度
            struct.pack('>Q', file_size) +                            # 文件大小
            digest +                                                  # SHA-256 摘要
            file_name_bytes                                           # 文件名
        ) 
        self._send(MSG_FILE_META, meta_payload) 
        # 分块发送文件数据  Send file data chunk by chunk
        with path_obj.open('rb') as f: 
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''): 
                self._send(MSG_FILE_CHUNK, chunk) 
        print(f'[*] File sent: {path_obj.name} ({file_size} bytes)') 
    def close(self) -> None: 
        """主动关闭连接  Close connection gracefully""" 
        if self.alive: 
            self._send(MSG_CLOSE, b'') 
        self.alive = False
        self.sock.close() 
    # ---------------- 内部方法  Internal Helpers ---------------- # 
    def _send(self, msg_type: int, payload: bytes) -> None: 
        """组装明文并发送  Assemble plaintext and send out""" 
        plaintext = struct.pack('B', msg_type) + payload
        encrypted = encrypt(self.key, plaintext) 
        with self.send_lock: 
            send_frame(self.sock, encrypted) 
    def _recv_loop(self) -> None: 
        """后台线程：连续接收并处理  Background receive loop""" 
        try: 
            while self.alive: 
                frame = recv_frame(self.sock)                         # 读取帧
                plaintext = decrypt(self.key, frame)                  # 解密
                self._dispatch(plaintext)                             # 分发
        except (EOFError, ValueError): 
            print('[*] Connection closed or authentication failed') 
        finally: 
            self.alive = False
            self.sock.close() 
    def _dispatch(self, plaintext: bytes) -> None: 
        """根据 type 分发处理  Dispatch by message type""" 
        msg_type = plaintext[0] 
        body = plaintext[1:] 
        if msg_type == MSG_TEXT: 
            print(f'\n[Peer] {body.decode(errors="replace")}') 
        elif msg_type == MSG_FILE_META: 
            self._init_file_reception(body) 
        elif msg_type == MSG_FILE_CHUNK: 
            self._handle_file_chunk(body) 
        elif msg_type == MSG_CLOSE: 
            print('[*] Peer closed connection') 
            self.alive = False
        else: 
            print(f'!! Unknown message type {msg_type}') 
    # -------- 文件接收：处理 FILE_META  Handle FILE_META -------- # 
    def _init_file_reception(self, payload: bytes) -> None: 
        """创建文件并保存 meta  Create file and store meta info""" 
        name_len = struct.unpack('>H', payload[:2])[0] 
        total_size = struct.unpack('>Q', payload[2:10])[0] 
        expected_digest = payload[10:42] 
        file_name = payload[42:42 + name_len].decode() 
        target_name = f'received_{file_name}' 
        f_handle = open(target_name, 'wb') 
        sha256 = hashlib.sha256() 
        self.incoming_file = (target_name, total_size, 0, 
                              f_handle, sha256, expected_digest) 
        print(f'\n[*] Receiving file: {file_name} → {target_name} ({total_size} bytes)') 
    # -------- 文件接收：写块  Handle FILE_CHUNK -------- # 
    def _handle_file_chunk(self, chunk: bytes) -> None: 
        if self.incoming_file is None: 
            print('!! Unexpected file chunk (no meta)') 
            return
        target_name, total_size, received, f_handle, sha256, exp_digest = self.incoming_file
        f_handle.write(chunk) 
        sha256.update(chunk) 
        received += len(chunk) 
        self.incoming_file = (target_name, total_size, received, 
                              f_handle, sha256, exp_digest) 
        percent = received / total_size * 100
        print(f'\r    Progress: {percent:6.2f} %', end='', flush=True) 
        if received >= total_size: 
            f_handle.close() 
            calc_digest = sha256.digest() 
            result = 'OK' if calc_digest == exp_digest else 'FAILED' 
            print(f'\n[*] File received ➜ {target_name} (SHA-256 {result})') 
            self.incoming_file = None
# ───────────────────────────────
# 握手函数  Handshake Function
# ───────────────────────────────
def perform_handshake(sock: socket.socket, is_server: bool) -> bytes: 
    """ 
    执行 X25519 握手并返回会话密钥。 
    Perform X25519 handshake and return session key. 
    """ 
    private_key = X25519PrivateKey.generate()
    # [修正] 按要求传递参数获得32字节raw公钥
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,          # 必须指定 encoding
        format=serialization.PublicFormat.Raw         # 必须指定 format
    )
    if is_server: 
        peer_pub = recv_frame(sock)            # 服务端先收 / server receives first
        send_frame(sock, public_bytes) 
    else: 
        send_frame(sock, public_bytes)         # 客户端先发 / client sends first
        peer_pub = recv_frame(sock) 
    peer_key = X25519PublicKey.from_public_bytes(peer_pub) 
    shared_secret = private_key.exchange(peer_key) 
    session_key = derive_key(shared_secret) 
    print('[*] Key exchange complete') 
    return session_key
# ───────────────────────────────
# 命令行交互  Command-Line Interface
# ───────────────────────────────
def cli_loop(conn: SecureConnection) -> None: 
    """ 
    简易 CLI： 
        输入文本   → 发送文本
        /f <path> → 发送文件
        /q        → 退出
    Simple CLI: 
        plain text → send text
        /f <path>  → send file
        /q         → quit
    """ 
    try: 
        while conn.alive: 
            user_in = input('> ').strip() 
            if not user_in: 
                continue
            if user_in == '/q': 
                conn.close(); break
            if user_in.startswith('/f '): 
                conn.send_file(user_in[3:].strip()) 
            else: 
                conn.send_text(user_in) 
    except (KeyboardInterrupt, EOFError): 
        conn.close() 
# ───────────────────────────────
# 服务器模式  Server Mode
# ───────────────────────────────
def run_server() -> None: 
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    listen_sock.bind(('0.0.0.0', TCP_PORT)) 
    listen_sock.listen(1) 
    print(f'[*] Listening on 0.0.0.0:{TCP_PORT}') 
    conn_sock, addr = listen_sock.accept() 
    print(f'[*] Connected from {addr}') 
    key = perform_handshake(conn_sock, is_server=True) 
    secure_conn = SecureConnection(conn_sock, key) 
    cli_loop(secure_conn) 

# ───────────────────────────────
# 客户端模式  Client Mode
# ───────────────────────────────
def run_client(server_ip: str) -> None: 
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    conn_sock.connect((server_ip, TCP_PORT)) 
    print(f'[*] Connected to {server_ip}:{TCP_PORT}') 
    key = perform_handshake(conn_sock, is_server=False) 
    secure_conn = SecureConnection(conn_sock, key) 
    cli_loop(secure_conn) 
# ───────────────────────────────
# 程序入口  Entry Point
# ───────────────────────────────
if __name__ == '__main__': 
    # 判断命令行参数  Decide mode by argv
    if len(sys.argv) == 2 and sys.argv[1].lower() == 'server': 
        run_server() 
    elif len(sys.argv) == 2: 
        run_client(sys.argv[1]) 
    else: 
        script_name = pathlib.Path(sys.argv[0]).name
        print(f'Usage 用法:\n' 
              f'  Server 服务器: python {script_name} server\n' 
              f'  Client 客户端: python {script_name} <server_ip>')
