#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secure_transfer.py
=====================================================================
  Overview
---------------------------------------------------------------------
This script implements a full-featured, production-ready secure TCP
file and message transfer tool in a single Python file.

---------------------------------------------------------------------
  Structure
---------------------------------------------------------------------
1. Imports (standard + third party)
2. Constants/Protocol type definitions
3. Utility functions (framing, crypto, key derivation)
4. SecureConnection class: Handles encrypted send/recv, file transfer
5. Handshake (key agreement) logic
6. Interactive CLI (command-line interaction)
7. Server and client main entry
8. __main__ section (mode selection by argv)

---------------------------------------------------------------------
  Protocol Specification (Wire Format)
---------------------------------------------------------------------
Port:
    5555 (default; changeable)

Handshake:
    - Each side generates X25519 keypair
    - Each sends its raw 32-byte public key (client first)
    - Shared secret: private.exchange(peer)
    - Session key: 32 bytes via HKDF-SHA256(info='SecureTransfer')

Encrypted frame (all traffic after handshake):
    [4-byte big-endian length prefix]
    [12-byte ChaCha20 nonce][16-byte tag][ciphertext]

Decrypted Frame Payload Format:
    [1 byte type][payload...]
        0x01: Text       [utf-8 encoded text]
        0x02: FileMeta   [2-byte fnameLen|8-byte size|32-byte digest|filename]
        0x03: FileChunk  [raw bytes, ≤64KiB]
        0x04: Close conn [empty payload]

File integrity:
    - Sender: precomputes SHA-256, places in FILE_META
    - Receiver: streams SHA-256, verifies at file end

---------------------------------------------------------------------
  Features
---------------------------------------------------------------------
- X25519 key exchange (ECDH)
- HKDF SHA-256 for session key
- ChaCha20-Poly1305 (PyCryptodome) AEAD encryption
- Threaded non-blocking send/recv
- Plaintext message and large file transfer (with integrity, chunked)
- Protocol and file integrity detailed above

=====================================================================
"""

# ─── Imports (Standard Library) ─────────────────────────────────────
import os                           # File I/O, randomness
import sys                          # Argument parsing
import socket                       # TCP sockets
import struct                       # Binary packing
import threading                    # For background recv
import pathlib                      # Path utilities
import hashlib                      # SHA-256 for files
from typing import Optional, Tuple, BinaryIO # Type hints

# ─── Imports (Third Party) ──────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)         # X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF
from cryptography.hazmat.primitives import hashes          # Hashing
from cryptography.hazmat.primitives import serialization   # For .public_bytes()
from Crypto.Cipher import ChaCha20_Poly1305               # AEAD encryption

# ─── Protocol / Format Constants ────────────────────────────────────
TCP_PORT: int = 5555                                    # Default port number

FILE_CHUNK_SIZE: int = 64 * 1024                        # 64 KiB file chunks
NONCE_SIZE: int = 12                                    # ChaCha20 nonce size
TAG_SIZE: int = 16                                      # ChaCha20 MAC size

MSG_TEXT: int = 0x01                                    # Text message type
MSG_FILE_META: int = 0x02                               # File meta info
MSG_FILE_CHUNK: int = 0x03                              # File content chunk
MSG_CLOSE: int = 0x04                                   # Close signal

# ─── Low-level Framing and Crypto Functions ─────────────────────────
def send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack('>I', len(data)) + data)      # Send with len prefix

def recv_frame(sock: socket.socket) -> bytes:
    length_prefix: bytes = sock.recv(4)                    # 4 byte length prefix
    if len(length_prefix) < 4:                             # Short means closed
        raise EOFError('connection closed (prefix)')
    frame_len: int = struct.unpack('>I', length_prefix)[0] # Length as int
    buffer: bytearray = bytearray()
    while len(buffer) < frame_len:                         # Read full payload
        chunk: bytes = sock.recv(frame_len - len(buffer))
        if not chunk: raise EOFError('connection closed (payload)')
        buffer.extend(chunk)
    return bytes(buffer)

def derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'SecureTransfer')
    return hkdf.derive(shared_secret)                     # 32 bytes session key

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)                        # Unique per frame
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext                       # [nonce|tag|ciphertext]

def decrypt(key: bytes, packet: bytes) -> bytes:
    nonce = packet[:NONCE_SIZE]
    tag = packet[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = packet[NONCE_SIZE + TAG_SIZE:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)     # Exception on tamper

# ─── SecureConnection: Threaded Encrypted Socket + File Transfer ────
class SecureConnection:
    """
    Secure TCP connection with completed handshake.
    All data sent/received is encrypted and authenticated.
    Runs a background thread for receiving.
    Provides high-level API: send_text(), send_file(), close().
    """
    def __init__(self, sock: socket.socket, key: bytes) -> None:
        self.sock: socket.socket = sock                          # Underlying TCP socket
        self.key: bytes = key                                    # Session key
        self.alive: bool = True                                  # Life flag for threads
        self.send_lock = threading.Lock()                        # Thread safety for send
        self.incoming_file: Optional[
            Tuple[str, int, int, BinaryIO, hashlib._Hash, bytes]
        ] = None                                                 # Receiving file state
        self.recv_thread = threading.Thread(target=self._recv_loop,daemon=True)
        self.recv_thread.start()                                 # Start receiver

    def send_text(self, text: str) -> None:
        """Send UTF-8 text message."""
        self._send(MSG_TEXT, text.encode())

    def send_file(self, path: str) -> None:
        """Send file with meta, chunked, and its SHA-256 integrity."""
        path_obj = pathlib.Path(path)                                            # Path object for file
        if not path_obj.is_file():
            print(f'!! File not found: {path}')
            return
        file_size = path_obj.stat().st_size                                     # File size in bytes
        file_name_bytes = path_obj.name.encode()                                # File name (bytes)
        sha256 = hashlib.sha256()                                               # For integrity
        with path_obj.open('rb') as f:
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''):
                sha256.update(chunk)
        digest = sha256.digest()                                                # SHA-256 digest

        meta_payload = (struct.pack('>H', len(file_name_bytes)) +
                        struct.pack('>Q', file_size) +
                        digest +
                        file_name_bytes)
        self._send(MSG_FILE_META, meta_payload)                                 # Send file meta

        with path_obj.open('rb') as f:
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''):
                self._send(MSG_FILE_CHUNK, chunk)                               # Send content chunks

        print(f'[*] File sent: {path_obj.name} ({file_size} bytes)')

    def close(self) -> None:
        """Send close signal and close socket."""
        if self.alive:
            self._send(MSG_CLOSE, b'')
        self.alive = False
        self.sock.close()

    def _send(self, msg_type: int, payload: bytes) -> None:
        plaintext = struct.pack('B', msg_type) + payload                        # 1 byte type + payload
        encrypted = encrypt(self.key, plaintext)
        with self.send_lock:
            send_frame(self.sock, encrypted)                                    # Encrypted frame

    def _recv_loop(self) -> None:
        """Background: receive, decrypt, dispatch frames."""
        try:
            while self.alive:
                frame = recv_frame(self.sock)
                plaintext = decrypt(self.key, frame)
                self._dispatch(plaintext)
        except (EOFError, ValueError):
            print('[*] Connection closed or authentication failed')
        finally:
            self.alive = False
            self.sock.close()

    def _dispatch(self, plaintext: bytes) -> None:
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

    def _init_file_reception(self, payload: bytes) -> None:
        name_len = struct.unpack('>H', payload[:2])[0]                       # Filename length
        total_size = struct.unpack('>Q', payload[2:10])[0]                   # File size
        expected_digest = payload[10:42]                                     # Sender's SHA-256
        file_name = payload[42:42 + name_len].decode()                       # Original filename
        target_name = f'received_{file_name}'                                # Output with prefix
        f_handle = open(target_name, 'wb')
        sha256 = hashlib.sha256()
        self.incoming_file = (target_name, total_size, 0, f_handle, sha256, expected_digest)
        print(f'\n[*] Receiving file: {file_name} → {target_name} ({total_size} bytes)')

    def _handle_file_chunk(self, chunk: bytes) -> None:
        if self.incoming_file is None:
            print('!! Unexpected file chunk (no meta)')
            return
        target_name, total_size, received, f_handle, sha256, exp_digest = self.incoming_file
        f_handle.write(chunk)
        sha256.update(chunk)
        received += len(chunk)
        self.incoming_file = (target_name, total_size, received, f_handle, sha256, exp_digest)
        percent = received / total_size * 100
        print(f'\r    Progress: {percent:6.2f} %', end='', flush=True)
        if received >= total_size:
            f_handle.close()
            calc_digest = sha256.digest()
            status = 'OK' if calc_digest == exp_digest else 'FAILED'
            print(f'\n[*] File received ➜ {target_name} (SHA-256 {status})')
            self.incoming_file = None

# ─── Handshake (X25519 key exchange + HKDF) ────────────────────────
def perform_handshake(sock: socket.socket, is_server: bool) -> bytes:
    """
    Exchange X25519 public keys, compute session key (32 bytes).
    Returns: session key
    """
    private_key = X25519PrivateKey.generate()                        # Generate new keypair
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )                                                               # 32-byte wire public
    if is_server:
        peer_pub = recv_frame(sock)                                 # Server receives first
        send_frame(sock, public_bytes)
    else:
        send_frame(sock, public_bytes)                              # Client sends first
        peer_pub = recv_frame(sock)
    peer_key = X25519PublicKey.from_public_bytes(peer_pub)          # Peer public key
    shared_secret = private_key.exchange(peer_key)                  # X25519 exchange
    session_key = derive_key(shared_secret)                         # HKDF → 32B session key
    print('[*] Key exchange complete')
    return session_key

# ─── Command-line User Interface ───────────────────────────────────
def cli_loop(conn: SecureConnection) -> None:
    """
    Interactive CLI:
    - <text>         : Send text message
    - /f <file_path> : Send file
    - /q             : Quit
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

# ─── Server Main ──────────────────────────────────────────────────
def run_server() -> None:
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP listen socket
    listen_sock.bind(('0.0.0.0', TCP_PORT))
    listen_sock.listen(1)
    print(f'[*] Listening on 0.0.0.0:{TCP_PORT}')
    conn_sock, addr = listen_sock.accept()
    print(f'[*] Connected from {addr}')
    key = perform_handshake(conn_sock, is_server=True)
    secure_conn = SecureConnection(conn_sock, key)
    cli_loop(secure_conn)

# ─── Client Main ──────────────────────────────────────────────────
def run_client(server_ip: str) -> None:
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((server_ip, TCP_PORT))
    print(f'[*] Connected to {server_ip}:{TCP_PORT}')
    key = perform_handshake(conn_sock, is_server=False)
    secure_conn = SecureConnection(conn_sock, key)
    cli_loop(secure_conn)

# ─── Entry Point ──────────────────────────────────────────────────
if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1].lower() == 'server':      # Run as server
        run_server()
    elif len(sys.argv) == 2:                                        # Run as client
        run_client(sys.argv[1])
    else:                                                           # Print usage
        script_name = pathlib.Path(sys.argv[0]).name
        print(f'Usage:\n'
              f'  Server: python {script_name} server\n'
              f'  Client: python {script_name} <server_ip>')
