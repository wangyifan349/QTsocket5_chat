#!/usr/bin/env
python3# -*- coding: utf-8 -*-
"""
secure_transfer_x25519_ephemeral_server.py —— **************************************
- Server每次启动临时生成X25519密钥对，不落盘，启动即输出公钥HEX给人肉交换   
- 完全端到端加密（文件/文本），ChaCha20Poly1305，分块发送，带SHA-256校验  
- 发送、接收互不阻塞，安全线程模型                                        
***********************************************************************************
"""
import os                           # 文件/系统操作      │
import sys                          # 命令行参数         │
import socket                       # 网络通信           │
import struct                       # 打包/解包二进制    │
import threading                    # 多线程             │
import pathlib                      # 路径操作           │
import hashlib                      # SHA-256校验        │
import binascii                     # HEX编码            │
from typing import Optional, Tuple, BinaryIO      # 类型提示掉错误 │
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey, X25519PublicKey) #X25519密钥对│
from cryptography.hazmat.primitives.kdf.hkdf import HKDF      #HKDF密钥派生      │
from cryptography.hazmat.primitives import hashes, serialization    #哈希/序列化│
from Crypto.Cipher import ChaCha20_Poly1305 # --- pip install pycryptodome ──────│
# ───────────── 协议参数 ─────────────
TCP_PORT        = 5555                                 # ⚑ 监听端口               │
FILE_CHUNK_SIZE = 64 * 1024                            # ⚑ 文件分块大小           │
NONCE_SIZE      = 12                                   # ⚑ ChaCha20随机数         │
TAG_SIZE        = 16                                   # ⚑ ChaCha20 MAC           │

MSG_TEXT        = 0x01                                 # ◇ 文本消息               │
MSG_FILE_META   = 0x02                                 # ◇ 文件元数据消息         │
MSG_FILE_CHUNK  = 0x03                                 # ◇ 文件分块消息           │
MSG_CLOSE       = 0x04                                 # ◇ 关闭信号               │

# ───────────── 网络帧 + 加解密 ─────────────
def send_frame(sock: socket.socket, data: bytes) -> None:              #──────────┐
    sock.sendall(struct.pack('>I', len(data)) + data)                  # 4字节长度+正文 │
                                                                        #──────────┘
def recv_frame(sock: socket.socket) -> bytes:                          #──────────┐
    length_prefix = recv_exact(sock, 4)                                # 长度前缀 │
    if len(length_prefix) < 4: raise EOFError('connection closed')     #
    frame_len = struct.unpack('>I', length_prefix)[0]                  #
    return recv_exact(sock, frame_len)                                 #──────────┘

def recv_exact(sock: socket.socket, sz: int) -> bytes:                 #──────────┐
    buf = bytearray()                                                  #
    while len(buf) < sz:                                               #
        chunk = sock.recv(sz - len(buf))                               #
        if not chunk: raise EOFError('connection closed')              #
        buf.extend(chunk)                                              #
    return bytes(buf)                                                  #──────────┘

def derive_session_key(shared_secret: bytes) -> bytes:                 #──────────┐
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,                  #
                salt=None, info=b'SecureTransfer')                     #
    return hkdf.derive(shared_secret)                                  #──────────┘

def encrypt_frame(key: bytes, plaintext: bytes) -> bytes:              #──────────┐
    nonce = os.urandom(NONCE_SIZE)                                     #
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)               #
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)             #
    return nonce + tag + ciphertext                                    #──────────┘

def decrypt_frame(key: bytes, packet: bytes) -> bytes:                 #──────────┐
    nonce = packet[:NONCE_SIZE]                                        #
    tag = packet[NONCE_SIZE:NONCE_SIZE+TAG_SIZE]                       #
    ciphertext = packet[NONCE_SIZE+TAG_SIZE:]                          #
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)               #
    return cipher.decrypt_and_verify(ciphertext, tag)                  #──────────┘

# ───────────── Ephemeral Server X25519 Handshake ─────────────
def server_handshake_ephemeral(sock: socket.socket) -> Tuple[bytes, str]:      #──┐
    # 启动时生成短暂私钥，只用1次不落盘。                                │
    server_priv = X25519PrivateKey.generate()                                 #
    server_pub_bytes = server_priv.public_key().public_bytes(                 #
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)            #
    pubkeyhex = binascii.hexlify(server_pub_bytes).decode()                   #
    print("\n[★] 本次服务端的公钥HEX:", pubkeyhex)                               #
    print("[★] 用电话or聊天工具给客户端, 客户端要人工粘贴作为安全锚")              #
    print("[★] 每次会话唯一，彻底规避本地密钥存储和中间人攻击")                      #
    client_pub_bytes = recv_exact(sock, 32)                                   #
    client_pubkey = X25519PublicKey.from_public_bytes(client_pub_bytes)       #
    shared_secret = server_priv.exchange(client_pubkey)                       #
    session_key = derive_session_key(shared_secret)                           #
    print('[*] 握手OK，安全通道已建立')                                         #
    return session_key, pubkeyhex                                             #──┘

def client_handshake(sock: socket.socket, server_pubkey_hex: str) -> bytes:   #──┐
    # 人工输入服务端公钥（HEX）。客户端ephemeral key协商                        │
    server_pubkey_bytes = binascii.unhexlify(server_pubkey_hex)               #
    server_pubkey = X25519PublicKey.from_public_bytes(server_pubkey_bytes)    #
    client_priv = X25519PrivateKey.generate()                                 #
    client_pub_bytes = client_priv.public_key().public_bytes(                 #
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)            #
    sock.sendall(client_pub_bytes)                                            #
    shared_secret = client_priv.exchange(server_pubkey)                       #
    session_key = derive_session_key(shared_secret)                           #
    print('[*] 握手OK，安全通道已建立')                                         #
    return session_key                                                        #──┘
# ───────────── 安全通道 SecureConnection 类 ─────────────
class SecureConnection:                                                   #────┐
    def __init__(self, sock: socket.socket, session_key: bytes) -> None:  #
        self.sock         = sock                                          #
        self.session_key  = session_key                                   #
        self.alive        = True                                          #
        self.send_lock    = threading.Lock()                              #
        self.incoming_file= None   # type: ignore                         #
        self.recv_thread  = threading.Thread(target=self._recv_loop, daemon=True)  #
        self.recv_thread.start()                                          #────┘

    def send_text(self, text: str) -> None:                               #────┐
        self._send(MSG_TEXT, text.encode())                               #────┘

    def send_file(self, filepath: str) -> None:                           #────┐
        fpath = pathlib.Path(filepath)                                    #
        if not fpath.is_file():                                           #
            print(f"[!!] 文件不存在: {filepath}")                         #
            return                                                       #
        fname_bytes = fpath.name.encode()                                 #
        fsize = fpath.stat().st_size                                      #
        sha256 = hashlib.sha256()                                         #
        with fpath.open('rb') as f:                                       #
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''):      #
                sha256.update(chunk)                                      #
        digest = sha256.digest()                                          #
        meta = (struct.pack('>H', len(fname_bytes)) +                     #
                struct.pack('>Q', fsize) +                                #
                digest + fname_bytes)                                     #
        self._send(MSG_FILE_META, meta)                                   #
        with fpath.open('rb') as f:                                       #
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''):      #
                self._send(MSG_FILE_CHUNK, chunk)                         #
        print(f"[*] 文件已发送: {fpath.name} ({fsize} bytes)")            #────┘

    def close(self) -> None:                                              #────┐
        if self.alive:                                                    #
            self._send(MSG_CLOSE, b'')                                    #
        self.alive = False                                                #
        self.sock.close()                                                 #────┘

    def _send(self, msg_type: int, payload: bytes) -> None:               #────┐
        plaintext = struct.pack('B', msg_type) + payload                  #
        encrypted = encrypt_frame(self.session_key, plaintext)            #
        with self.send_lock:                                              #
            send_frame(self.sock, encrypted)                              #────┘

    def _recv_loop(self) -> None:                                         #────┐
        try:                                                             #
            while self.alive:                                            #
                frame = recv_frame(self.sock)                            #
                try:                                                     #
                    plaintext = decrypt_frame(self.session_key, frame)    #
                except Exception:                                        #
                    print("[!!] 数据包认证或解密错误！")                  #
                    self.alive = False                                   #
                    break                                                #
                self._dispatch(plaintext)                                #
        except (EOFError, OSError):                                      #
            print("[*] 连接关闭")                                         #
        finally:                                                         #
            self.alive = False                                           #
            self.sock.close()                                            #────┘

    def _dispatch(self, plaintext: bytes) -> None:                        #────┐
        msg_type = plaintext[0]                                          #
        msg_body = plaintext[1:]                                         #
        if msg_type == MSG_TEXT:                                         #
            print(f"\n[Peer] {msg_body.decode(errors='replace')}")        #
        elif msg_type == MSG_FILE_META:                                  #
            self._handle_file_meta(msg_body)                             #
        elif msg_type == MSG_FILE_CHUNK:                                 #
            self._handle_file_chunk(msg_body)                            #
        elif msg_type == MSG_CLOSE:                                      #
            print('[*] Peer closed connection')                          #
            self.alive = False                                           #
        else:                                                           #
            print(f"[!!] 未知消息类型: {msg_type}")                      #────┘

    def _handle_file_meta(self, payload: bytes) -> None:                  #────┐
        fname_len = struct.unpack('>H', payload[:2])[0]                  #
        total_size = struct.unpack('>Q', payload[2:10])[0]               #
        expected_digest = payload[10:42]                                 #
        fname = payload[42:42+fname_len].decode()                        #
        target = f"received_{fname}"                                     #
        fobj = open(target, 'wb')                                        #
        sha256 = hashlib.sha256()                                        #
        self.incoming_file = (target, total_size, 0, fobj, sha256, expected_digest)  #
        print(f"\n[*] 开始接收文件: {fname} → {target} ({total_size} bytes)")         #────┘

    def _handle_file_chunk(self, chunk: bytes) -> None:                   #────┐
        if self.incoming_file is None:                                   #
            print('[!!] 未收到文件元信息却有分块')                        #
            return                                                      #
        target, total, received, fobj, sha256, expected_digest = self.incoming_file #
        fobj.write(chunk)                                               #
        sha256.update(chunk)                                            #
        received += len(chunk)                                          #
        self.incoming_file = (target, total, received, fobj, sha256, expected_digest)#
        percent = received / total * 100                                #
        print(f"\r    进度: {percent:6.2f} %", end='', flush=True)      #
        if received >= total:                                           #
            fobj.close()                                                #
            actual_digest = sha256.digest()                             #
            verify = "OK" if actual_digest == expected_digest else "FAILED"         #
            print(f"\n[*] 文件接收完毕 ➜ {target} (SHA-256 校验 {verify})")           #
            self.incoming_file = None                                   #────┘
# ───────────── 命令行交互界面 ─────────────
def command_line_interface(conn: SecureConnection) -> None:              #────┐
    print("命令: 普通消息, /f <文件> 发文件, /q 退出")                   #
    try:                                                                #
        while conn.alive:                                               #
            line = input('> ').strip()                                  #
            if not line: continue                                       #
            if line == '/q': conn.close(); break                        #
            if line.startswith('/f '): conn.send_file(line[3:].strip()) #
            else: conn.send_text(line)                                  #
    except (KeyboardInterrupt, EOFError):                               #
        conn.close()                                                    #────┘
# ───────────── 服务器启动流程 ─────────────
def run_server():
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      #
    listen_sock.bind(('0.0.0.0', TCP_PORT))                             #
    listen_sock.listen(1)                                               #
    print(f'[*] 监听 0.0.0.0:{TCP_PORT}')                                #
    conn_sock, addr = listen_sock.accept()                              #
    print(f'[*] 已连接: {addr}')                                         #
    session_key, pubkeyhex = server_handshake_ephemeral(conn_sock)      #
    conn = SecureConnection(conn_sock, session_key)                     #
    command_line_interface(conn)                                        #
# ───────────── 客户端启动流程 ─────────────
def run_client(server_ip: str):
    print(f"[*] 连接到 {server_ip}:{TCP_PORT}")                          #
    server_pubkey_hex = input("[*] 粘贴服务端公钥HEX: ").strip()         #
    if not server_pubkey_hex or len(server_pubkey_hex) != 64:           #
        print("[!!] 公钥HEX必须64位")                                    #
        sys.exit(1)                                                     #
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)       #
    conn_sock.connect((server_ip, TCP_PORT))                            #
    session_key = client_handshake(conn_sock, server_pubkey_hex)        #
    conn = SecureConnection(conn_sock, session_key)                     #
    command_line_interface(conn)                                        #
# ───────────── 用法提示 ─────────────
def print_usage(script_name):
    print( "用法:\n"
          f"  服务器端: python {script_name} server\n"
          f"  客户端  : python {script_name} <服务端IP>\n"
           "  启动后, 客户端需人工粘贴服务端公钥HEX, 人肉比对, 核心完全端到端."
            "\n  /f 路径 发送文件; /q 退出"
    )
if __name__ == '__main__':
    script_name = pathlib.Path(sys.argv[0]).name
    if len(sys.argv) == 2 and sys.argv[1].lower() == 'server':
        run_server()
    elif len(sys.argv) == 2:
        run_client(sys.argv[1])
    else:
        print_usage(script_name)
