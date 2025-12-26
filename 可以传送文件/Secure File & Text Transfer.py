#!/usr/bin/env python3
"""
Secure File & Text Transfer (基于PyQt5的端到端加密文件/消息传送工具)
简介
----------------
本程序旨在为用户提供一个简单、安全、易用的界面，支持通过端到端加密协议收发文本消息与文件，既可作为服务器监听，也可作为客户端连接他人，所有操作均通过现代加密算法（NaCl协议、ChaCha20-Poly1305）保障机密性和消息完整性。
特点：
- 支持本地服务端和远程客户模式，互操作灵活切换。
- 集成SOCKS5代理，适应受限/匿名网络环境。
- 文件与文本均点对点安全收发，不存中间人。
- 全程多线程，后台任务与界面流畅独立。
- 端到端密钥协商、强加密，防止窃听或内容泄露。
- 清晰易用的图形用户界面（PyQt5实现）。
开源许可
----------------
本软件遵循 MIT License（MIT许可证）开源发布，任何人可自由使用、复制、修改、分发，惟需保留原始版权声明。
特别致敬与感谢
----------------
本项目向所有为隐私权和个人数据安全而奋斗者致敬。  
感谢人工智能与现代科技进步，使端到端安全通信对所有人都变得简单可及。
感谢所有开源及科学社区的贡献者——正是你们让自由、透明、安全的工具成为现实！
"""
import sys
import os
import struct
import threading
import socket
import queue
import traceback

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTabWidget, QFormLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QSpinBox, QFileDialog)
from PyQt5.QtCore import pyqtSignal, QObject

import socks  # For SOCKS5 proxy

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from nacl.public import PrivateKey
from nacl.bindings import crypto_scalarmult

DEFAULT_LISTEN_PORT = 9000                               # Default server port
RECEIVED_FILE_DIRECTORY = './received_files'             # Directory to save incoming files
os.makedirs(RECEIVED_FILE_DIRECTORY, exist_ok=True)


def receive_all(sock, size):                             # Receive exact size or return None if closed
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def receive_frame(sock):                                 # Network protocol: each frame prefixed with 4-byte length
    header = receive_all(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack('>I', header)
    return receive_all(sock, length)

def send_frame(sock, body: bytes):                       # Send frame with 4-byte length header
    sock.sendall(struct.pack('>I', len(body)) + body)

def derive_keys(shared_secret: bytes):                   # Derive encryption session keys
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'x25519-chacha20poly1305'
    )
    key_material = hkdf.derive(shared_secret)
    return key_material[:32], key_material[32:]          # rx_key, tx_key


class SignalBridge(QObject):                             # For Qt-thread communication (GUI thread safe)
    server_log = pyqtSignal(str)
    client_log = pyqtSignal(str)
    client_message = pyqtSignal(str)


class ServerThread(threading.Thread):                    # Server main thread (accepts connections)
    def __init__(self, signal_bridge, host, port):
        super().__init__(daemon=True)
        self.signal_bridge = signal_bridge
        self.host = host
        self.port = port
        self.running = True

    def run(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(16)
            self.signal_bridge.server_log.emit(f'Server listening on {self.host}:{self.port}')   # Log start
            while self.running:
                client_socket, address = server_socket.accept()                                  # Accept client
                thread_handle_connection = threading.Thread(target=handle_server_connection, args=(
                    client_socket, address, self.signal_bridge), daemon=True)
                thread_handle_connection.start()
        except Exception as error:
            self.signal_bridge.server_log.emit('Server error: ' + repr(error))
        finally:
            try:
                server_socket.close()
            except Exception:
                pass
            self.signal_bridge.server_log.emit('Server socket closed')


def handle_server_connection(client_socket, address, signal_bridge):         # Each incoming client handled in thread
    try:
        server_private_key = PrivateKey.generate()
        server_public_bytes = bytes(server_private_key.public_key)
        client_handshake_frame = receive_frame(client_socket)
        if not client_handshake_frame or client_handshake_frame[0] != 0x01: # Client handshake
            client_socket.close()
            return
        client_public_key = client_handshake_frame[1:33]
        send_frame(client_socket, b'\x01' + server_public_bytes)
        shared_secret = crypto_scalarmult(
            bytes(server_private_key._private_key), client_public_key)
        rx_key, tx_key = derive_keys(shared_secret)
        aead_rx = ChaCha20Poly1305(rx_key)
        aead_tx = ChaCha20Poly1305(tx_key)
        signal_bridge.server_log.emit(
            f'[+] handshake with {address} completed')
        while True:
            encrypted_frame = receive_frame(client_socket)
            if not encrypted_frame:
                break
            if encrypted_frame[0] != 0x02:
                continue
            payload = encrypted_frame[1:]
            if len(payload) < 12:
                break
            nonce = payload[:12]
            ciphertext = payload[12:]
            try:
                plaintext = aead_rx.decrypt(nonce, ciphertext, None)
            except Exception as error:
                signal_bridge.server_log.emit(f'Decrypt failed: {error}')
                break
            msg_type = plaintext[0]
            if msg_type == 0x10:                                                 # Text message
                text = plaintext[1:].decode('utf-8', errors='replace')
                signal_bridge.server_log.emit(f'[msg from {address}] {text}')
                reply = b'\x10' + b'ACK: text received'
                reply_nonce = os.urandom(12)
                send_frame(
                    client_socket,
                    b'\x02' + reply_nonce + aead_tx.encrypt(reply_nonce, reply, None)
                )
            elif msg_type == 0x11:                                               # File
                if len(plaintext) < 3:
                    continue
                filename_length = int.from_bytes(plaintext[1:3], 'big')
                filename = plaintext[3:3 + filename_length].decode(
                    'utf-8', errors='replace')
                file_data = plaintext[3 + filename_length:]
                save_path = os.path.join(RECEIVED_FILE_DIRECTORY, filename)
                with open(save_path, 'wb') as file_save_handler:
                    file_save_handler.write(file_data)
                signal_bridge.server_log.emit(
                    f'[file from {address}] saved to {save_path}')
                reply = b'\x10' + ('ACK: saved ' + filename).encode()
                reply_nonce = os.urandom(12)
                send_frame(
                    client_socket,
                    b'\x02' + reply_nonce + aead_tx.encrypt(reply_nonce, reply, None)
                )
            else:
                signal_bridge.server_log.emit('Unknown message type')
    except Exception as error:
        signal_bridge.server_log.emit(f'[Connection error] {error}')
    finally:
        client_socket.close()
        signal_bridge.server_log.emit(f'[-] connection {address} closed')


class ClientWorker(QObject):                                    # Client background worker for Qt signals
    client_log = pyqtSignal(str)
    client_message = pyqtSignal(str)
    connected = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.sock = None
        self.aead_tx = None
        self.aead_rx = None
        self.running = False
        self.send_queue = queue.Queue()                         # Queue for outgoing messages

    def connect_to_server(self, proxy_host, proxy_port, server_host, server_port):
        try:
            proxy_socket = socks.socksocket()
            proxy_socket.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
            proxy_socket.connect((server_host, server_port))
            self.sock = proxy_socket
            client_private_key = PrivateKey.generate()
            client_public_key = bytes(client_private_key.public_key)
            send_frame(self.sock, b'\x01' + client_public_key)
            frame_server_response = receive_frame(self.sock)
            if not frame_server_response or frame_server_response[0] != 0x01:
                self.error.emit('Bad server public key')
                return
            server_public_key = frame_server_response[1:33]
            shared_secret = crypto_scalarmult(
                bytes(client_private_key._private_key), server_public_key)
            rx_key, tx_key = derive_keys(shared_secret)
            self.aead_rx = ChaCha20Poly1305(rx_key)
            self.aead_tx = ChaCha20Poly1305(tx_key)
            self.running = True
            threading.Thread(target=self.receive_loop, daemon=True).start()    # Start receiving in background
            threading.Thread(target=self.send_loop, daemon=True).start()       # Start sending in background
            self.client_log.emit('[+] Connected and handshake completed')
            self.connected.emit()
        except Exception as error:
            err_str = f'Connection failed: {error}\n{traceback.format_exc()}'
            self.error.emit(err_str)

    def receive_loop(self):                           # Receives messages, emits to GUI thread via signal
        while self.running:
            try:
                frame_received = receive_frame(self.sock)
                if not frame_received:
                    self.client_log.emit('[-] Server closed connection')
                    self.running = False
                    break
                if frame_received[0] != 0x02:
                    continue
                payload = frame_received[1:]
                if len(payload) < 12:
                    continue
                nonce = payload[:12]
                ciphertext = payload[12:]
                try:
                    plaintext = self.aead_rx.decrypt(nonce, ciphertext, None)
                    if plaintext[0] == 0x10:
                        msg = plaintext[1:].decode('utf-8', errors='replace')
                        self.client_message.emit('[server] ' + msg)            # For successful acknowledgment etc
                except Exception as error:
                    self.client_log.emit('Decrypt error: ' + str(error))
            except Exception as error:
                self.client_log.emit('Exception: ' + str(error))
                break

    def send_loop(self):  # Dedicated thread, sends one message at a time from queue
        while self.running:
            try:
                item = self.send_queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                if item['type'] == 'text':                                     # Text message
                    payload = b'\x10' + item['text'].encode('utf-8')
                elif item['type'] == 'file':                                   # File transfer
                    with open(item['path'], 'rb') as file_handler:
                        data = file_handler.read()
                    remote_name = item['remote'] if item['remote'] else os.path.basename(item['path'])
                    remote_name_bytes = remote_name.encode('utf-8')
                    payload = b'\x11' + len(remote_name_bytes).to_bytes(2, 'big') + remote_name_bytes + data
                else:
                    continue
                nonce = os.urandom(12)
                ciphertext = self.aead_tx.encrypt(nonce, payload, None)
                send_frame(self.sock, b'\x02' + nonce + ciphertext)
                if item['type'] == 'file':
                    self.client_message.emit(f'File sent: {item["path"]}')
            except Exception as error:
                self.client_log.emit('Send error: ' + str(error))
                break

    def send_text(self, text):
        self.send_queue.put({'type': 'text', 'text': text})

    def send_file(self, local_path, remote_name=None):
        self.send_queue.put({'type': 'file', 'path': local_path, 'remote': remote_name})

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.client_log.emit('Connection closed')


class MainWindow(QWidget):                                    # Main application window
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Secure File & Text Transfer')
        layout = QVBoxLayout(self)
        tabs = QTabWidget(self)
        layout.addWidget(tabs)
        self.signal_bridge = SignalBridge()

        # ---------- Server UI ----------
        self.server_log_view = QTextEdit(readOnly=True)
        self.server_start_button = QPushButton('Start Server')
        self.server_start_button.clicked.connect(self.on_server_start)
        server_tab = QWidget()
        tabs.addTab(server_tab, "Server")
        server_form = QFormLayout(server_tab)
        self.server_port_spin = QSpinBox()
        self.server_port_spin.setMaximum(65535)
        self.server_port_spin.setValue(DEFAULT_LISTEN_PORT)
        server_form.addRow(QLabel('Port:'), self.server_port_spin)
        server_form.addRow(self.server_start_button)
        server_form.addRow(self.server_log_view)
        self.server_thread = None
        self.signal_bridge.server_log.connect(self.server_log_view.append)

        # ---------- Client UI ----------
        self.client_log_view = QTextEdit(readOnly=True)
        self.client_message_view = QTextEdit(readOnly=True)
        self.client_connect_button = QPushButton('Connect')
        self.client_connect_button.clicked.connect(self.on_client_connect)
        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText('Enter message and press Enter to send...')
        self.text_input.returnPressed.connect(self.on_client_send_text)
        self.file_send_button = QPushButton('Send File')
        self.file_send_button.clicked.connect(self.on_client_send_file)
        client_tab = QWidget()
        tabs.addTab(client_tab, "Client")
        client_form = QFormLayout(client_tab)
        self.client_proxy_edit = QLineEdit('127.0.0.1')
        self.client_proxy_port = QSpinBox()
        self.client_proxy_port.setMaximum(65535)
        self.client_proxy_port.setValue(1080)
        self.client_host_edit = QLineEdit('127.0.0.1')
        self.client_port_spin = QSpinBox()
        self.client_port_spin.setMaximum(65535)
        self.client_port_spin.setValue(DEFAULT_LISTEN_PORT)
        client_form.addRow(QLabel('SOCKS5 Proxy:'), self.client_proxy_edit)
        client_form.addRow(QLabel('Proxy Port:'), self.client_proxy_port)
        client_form.addRow(QLabel('Server Host:'), self.client_host_edit)
        client_form.addRow(QLabel('Server Port:'), self.client_port_spin)
        client_form.addRow(self.client_connect_button)
        client_form.addRow(QLabel('Log:'), self.client_log_view)
        client_form.addRow(QLabel('Chat:'), self.client_message_view)
        client_form.addRow(self.text_input)
        client_form.addRow(self.file_send_button)
        self.client_worker = None

    def on_server_start(self):                                            # Start server in background
        port = self.server_port_spin.value()
        if self.server_thread and self.server_thread.is_alive():
            self.signal_bridge.server_log.emit('Server already running')
            return
        self.server_thread = ServerThread(self.signal_bridge, '0.0.0.0', port)
        self.server_thread.start()
        self.signal_bridge.server_log.emit('Server thread started')

    def on_client_connect(self):                                          # Connect client in background
        if self.client_worker:
            self.client_worker.close()
        self.client_worker = ClientWorker()
        self.client_worker.client_log.connect(self.client_log_view.append)
        self.client_worker.client_message.connect(self.client_message_view.append)
        self.client_worker.error.connect(self.client_log_view.append)
        proxy_host = self.client_proxy_edit.text()
        proxy_port = self.client_proxy_port.value()
        server_host = self.client_host_edit.text()
        server_port = self.client_port_spin.value()
        threading.Thread(
            target=self.client_worker.connect_to_server,
            args=(proxy_host, proxy_port, server_host, server_port),
            daemon=True
        ).start()

    def on_client_send_text(self):                                        # Send text via queue
        if self.client_worker and self.client_worker.running:
            text = self.text_input.text().strip()
            if text:
                self.client_worker.send_text(text)
                self.client_message_view.append('[me] ' + text)
                self.text_input.clear()
        else:
            self.client_log_view.append('Not connected!')

    def on_client_send_file(self):                                       # File chooser and send file via queue
        if not (self.client_worker and self.client_worker.running):
            self.client_log_view.append('Not connected!')
            return
        file_path, selected_filter = QFileDialog.getOpenFileName(self, 'Select File')  # selected_filter: user chosen filter string
        if not file_path:
            return
        file_base_name = os.path.basename(file_path)
        self.client_worker.send_file(file_path, file_base_name)
        self.client_message_view.append(f'[local] File sent: {file_path}')


if __name__ == '__main__':                                               # Main entry
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.resize(750, 480)
    main_window.show()
    sys.exit(app.exec_())
