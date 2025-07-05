import socket
import threading
import json
import base64
import os
import math
import time
import sys
import hashlib
from datetime import datetime
from queue import Queue, Empty
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socks

def get_current_time_string():  # 获取当前时间字符串
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_status(message):  # 打印带时间戳的状态消息
    print(f"[{get_current_time_string()}] {message}")

def create_packet(packet_type, payload_dictionary):  # 创建带类型的JSON字符串
    packet = {'type': packet_type}
    packet.update(payload_dictionary)
    return json.dumps(packet)

def parse_packet_from_bytes(data_bytes):  # 解析JSON包，失败返回None
    try:
        return json.loads(data_bytes.decode('utf-8'))
    except:
        return None

def encrypt_message_with_aes_gcm(aesgcm_instance, plaintext_string):  # AES-GCM加密字符串
    nonce = os.urandom(12)  # 12字节随机nonce
    ciphertext = aesgcm_instance.encrypt(nonce, plaintext_string.encode('utf-8'), None)
    packet = {'nonce': base64.b64encode(nonce).decode('utf-8'),
              'ciphertext': base64.b64encode(ciphertext).decode('utf-8')}
    return json.dumps(packet).encode('utf-8')

def decrypt_message_with_aes_gcm(aesgcm_instance, encrypted_bytes):  # AES-GCM解密
    try:
        packet = json.loads(encrypted_bytes.decode('utf-8'))
        nonce = base64.b64decode(packet['nonce'])
        ciphertext = base64.b64decode(packet['ciphertext'])
        plaintext_bytes = aesgcm_instance.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')
    except Exception as exception:
        print_status(f"Decrypt error: {exception}")
        return None

def derive_aes_key_with_hkdf(shared_secret_key_bytes, iterations=1000, key_length=32):  # HKDF迭代推导AES密钥
    derived_key = shared_secret_key_bytes
    for iteration_index in range(iterations):
        hkdf_instance = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'chat app derived key',  # 自定义上下文
        )
        derived_key = hkdf_instance.derive(derived_key)
        if iteration_index % 200 == 0:
            print_status(f"HKDF iteration progress: {iteration_index}/{iterations}")
    return derived_key

class FileReceiver:
    def __init__(self):
        self.lock_object = threading.Lock()  # 线程锁保护文件写操作
        self.file_path = None
        self.total_file_size = 0
        self.total_chunks_expected = 0
        self.chunks_received_set = set()
        self.total_bytes_received = 0
        self.file_object = None
        self.expected_file_sha256 = None

    def start_file_reception(self, filename, filesize, chunks_expected, expected_sha256):
        with self.lock_object:
            self.file_path = "received_" + os.path.basename(filename)
            self.total_file_size = filesize
            self.total_chunks_expected = chunks_expected
            self.chunks_received_set.clear()
            self.total_bytes_received = 0
            self.expected_file_sha256 = expected_sha256.lower() if expected_sha256 else None
            if self.file_object:
                self.file_object.close()
            self.file_object = open(self.file_path, 'wb')
            print_status(f"Prepare receiving file: {self.file_path} size={filesize} bytes, chunks={chunks_expected}, expected SHA256={self.expected_file_sha256}")

    def write_file_chunk(self, chunk_index, chunk_data_bytes):
        with self.lock_object:
            if chunk_index in self.chunks_received_set:
                print_status(f"Duplicate file chunk {chunk_index} received; dropping")
                return False
            self.file_object.seek(chunk_index * 16 * 1024)  # 定位写入分片偏移
            self.file_object.write(chunk_data_bytes)
            self.chunks_received_set.add(chunk_index)
            self.total_bytes_received += len(chunk_data_bytes)
            print_status(f"Received file chunk {chunk_index + 1}/{self.total_chunks_expected}, total bytes {self.total_bytes_received}/{self.total_file_size}")
            # 判断是否接收完毕
            if len(self.chunks_received_set) >= self.total_chunks_expected or self.total_bytes_received >= self.total_file_size:
                self.file_object.close()  # 关闭文件
                actual_file_hash = self.calculate_file_sha256()
                if self.expected_file_sha256 == actual_file_hash:
                    print_status(f"File received successfully and SHA256 verified: {self.file_path}")
                else:
                    print_status(f"File SHA256 mismatch! Actual hash: {actual_file_hash}")
                return True  # 文件接收完成
            return False

    def calculate_file_sha256(self):
        sha256_hasher = hashlib.sha256()
        with open(self.file_path, 'rb') as file_reader:
            while True:
                data_chunk = file_reader.read(65536)
                if not data_chunk:
                    break
                sha256_hasher.update(data_chunk)
        return sha256_hasher.hexdigest()

class ClientHandler(threading.Thread):
    def __init__(self, socket_connection, client_address):
        super().__init__(daemon=True)
        self.socket_connection = socket_connection
        self.client_address = client_address
        self.aesgcm_instance = None
        self.is_running = True
        self.file_receiver_instance = FileReceiver()

        self.send_lock = threading.Lock()
        self.pending_messages = dict()  # message_id: (encrypted_bytes, last_send_timestamp)
        self.send_queue = Queue()
        self.current_message_id = 0  # 消息ID自增

    def generate_next_message_id(self):
        with self.send_lock:
            self.current_message_id += 1
            return self.current_message_id

    def run(self):
        print_status(f"Connected client {self.client_address}")
        self.aesgcm_instance = self.perform_x25519_handshake()
        if not self.aesgcm_instance:
            print_status(f"Handshake failed, closing connection {self.client_address}")
            self.socket_connection.close()
            return
        try:
            self.is_running = True
            self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.send_thread = threading.Thread(target=self.send_loop, daemon=True)
            self.receive_thread.start()
            self.send_thread.start()
            self.receive_thread.join()
            self.send_thread.join()
        except Exception as exception:
            print_status(f"Exception in connection {self.client_address}: {exception}")
        finally:
            self.is_running = False
            self.socket_connection.close()
            print_status(f"Connection closed {self.client_address}")

    def perform_x25519_handshake(self):
        try:
            server_private_key = x25519.X25519PrivateKey.generate()  # 生成私钥
            server_public_key = server_private_key.public_key()  # 生成公钥
            serialized_public_bytes = server_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.socket_connection.sendall(serialized_public_bytes)  # 发送公钥
            client_public_bytes = self.socket_connection.recv(32)  # 接收客户端公钥
            if len(client_public_bytes) != 32:
                print_status("Handshake failed: client public key length incorrect")
                return None
            client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_bytes)
            shared_secret = server_private_key.exchange(client_public_key)  # 计算共享密钥
            print_status(f"Handshake shared key (hex first 32 bytes): {shared_secret.hex()[:64]}")
            derived_aes_key = derive_aes_key_with_hkdf(shared_secret)  # 迭代HKDF派生AES密钥
            print_status(f"HKDF derived AES key (hex first 32 bytes): {derived_aes_key.hex()[:64]}")
            return AESGCM(derived_aes_key)  # 创建AESGCM对象
        except Exception as exception:
            print_status(f"Handshake exception: {exception}")
            return None

    def send_encrypted_data(self, encrypted_data_bytes):
        with self.send_lock:
            message_length = len(encrypted_data_bytes)
            self.socket_connection.sendall(message_length.to_bytes(4, 'big') + encrypted_data_bytes)  # 发送4字节长度+数据

    def send_loop(self):
        RETRANSMIT_TIMEOUT = 5  # 重传超时秒数
        while self.is_running:
            try:
                try:
                    packet_dict = self.send_queue.get(timeout=0.5)
                    message_id = self.generate_next_message_id()
                    packet_dict['message_id'] = message_id  # 加message_id
                    plaintext_packet = create_packet(packet_dict['type'], {key:value for key,value in packet_dict.items() if key != 'type'})
                    encrypted_packet = encrypt_message_with_aes_gcm(self.aesgcm_instance, plaintext_packet)
                    self.send_encrypted_data(encrypted_packet)
                    with self.send_lock:
                        self.pending_messages[message_id] = (encrypted_packet, time.time())  # 记录未确认消息及发送时间
                    if packet_dict['type'] == 'text':
                        print_status(f"Sent message id={message_id}: {packet_dict.get('message','')}")
                    elif packet_dict['type'] == 'file_info':
                        print_status(f"Sent file info id={message_id}")
                    elif packet_dict['type'] == 'file':
                        print_status(f"Sent file chunk id={message_id} index={packet_dict.get('index')}")
                except Empty:  # 队列空就跳过
                    pass

                current_time_stamp = time.time()
                retransmit_candidates = []
                with self.send_lock:
                    for msg_id, (data_bytes, last_send_time) in self.pending_messages.items():
                        # 超时未确认的消息需要重传
                        if current_time_stamp - last_send_time > RETRANSMIT_TIMEOUT:
                            retransmit_candidates.append((msg_id, data_bytes))
                    for msg_id, data_bytes in retransmit_candidates:
                        print_status(f"Retransmitting message id={msg_id}")
                        self.send_encrypted_data(data_bytes)
                        self.pending_messages[msg_id] = (data_bytes, current_time_stamp)  # 更新时间戳
            except Exception as exception:
                print_status(f"Send loop exception: {exception}")
                self.is_running = False
                break

    def handle_acknowledgement(self, ack_id):
        with self.send_lock:
            if ack_id in self.pending_messages:  # 收到确认从缓存删除
                print_status(f"Received ACK id={ack_id}, removing from pending")
                del self.pending_messages[ack_id]

    def receive_loop(self):
        while self.is_running:
            try:
                header_bytes = self.socket_connection.recv(4)  # 读包头长度
                if not header_bytes or len(header_bytes) < 4:
                    print_status(f"{self.client_address} disconnected or failed to read length")
                    self.is_running = False
                    break
                packet_length = int.from_bytes(header_bytes, 'big')
                if packet_length <= 0:
                    print_status(f"{self.client_address} invalid packet length")
                    self.is_running = False
                    break
                received_data = b''
                while len(received_data) < packet_length:  # 读满数据
                    chunk = self.socket_connection.recv(packet_length - len(received_data))
                    if not chunk:
                        break
                    received_data += chunk
                if len(received_data) < packet_length:
                    print_status(f"{self.client_address} incomplete packet, disconnecting")
                    self.is_running = False
                    break
                decrypted_plaintext = decrypt_message_with_aes_gcm(self.aesgcm_instance, received_data)
                if decrypted_plaintext is None:
                    print_status("Failed to decrypt incoming packet; ignoring")
                    continue
                json_packet = parse_packet_from_bytes(decrypted_plaintext.encode('utf-8'))
                if not json_packet or 'type' not in json_packet:
                    print_status("Packet format error; ignoring")
                    continue
                packet_type = json_packet['type']
                if packet_type == 'ack':
                    ack_id = json_packet.get('ack_id')
                    if ack_id:
                        self.handle_acknowledgement(ack_id)
                else:
                    msg_id = json_packet.get('message_id')
                    if msg_id:
                        # 收到消息先回复ACK确认
                        ack_packet = create_packet('ack', {'ack_id': msg_id})
                        encrypted_ack = encrypt_message_with_aes_gcm(self.aesgcm_instance, ack_packet)
                        self.send_encrypted_data(encrypted_ack)
                    if packet_type == 'text':
                        message = json_packet.get('message', '')
                        print(f"\r[{get_current_time_string()}][{self.client_address}]: {message}\n>>> ", end='')
                    elif packet_type == 'file_info':
                        try:
                            self.file_receiver_instance.start_file_reception(json_packet['filename'], json_packet['filesize'], json_packet['chunks'], json_packet.get('sha256'))
                        except Exception as exception:
                            print_status(f"File info handling error: {exception}")
                    elif packet_type == 'file':
                        index = json_packet.get('index')
                        b64data = json_packet.get('data')
                        if index is None or b64data is None:
                            print_status("File chunk missing fields; ignoring")
                            continue
                        try:
                            data_bytes = base64.b64decode(b64data)
                        except Exception:
                            print_status("File chunk base64 decode failed; ignoring")
                            continue
                        self.file_receiver_instance.write_file_chunk(index, data_bytes)
                    else:
                        print_status(f"Unknown packet type: {packet_type}")
            except Exception as exception:
                print_status(f"Receive loop exception: {exception}")
                self.is_running = False
                break

def send_file_via_wrapper(wrapper_instance, filepath):
    if not os.path.isfile(filepath):
        print_status(f"File does not exist: {filepath}")
        return
    file_size = os.path.getsize(filepath)
    chunk_size = 16 * 1024  # 16KB
    total_chunks = math.ceil(file_size / chunk_size)
    filename = os.path.basename(filepath)
    sha256_value = calculate_file_sha256(filepath)
    print_status(f"Sending file: {filename} size={file_size} bytes, total chunks={total_chunks}, SHA256={sha256_value}")

    # 先发文件信息包
    wrapper_instance.send_queue.put({'type':'file_info',
                                     'filename': filename,
                                     'filesize': file_size,
                                     'chunks': total_chunks,
                                     'sha256': sha256_value})
    with open(filepath, 'rb') as f:
        for chunk_index in range(total_chunks):
            chunk = f.read(chunk_size)
            b64_chunk = base64.b64encode(chunk).decode('utf-8')
            wrapper_instance.send_queue.put({'type':'file','index': chunk_index, 'data': b64_chunk})

def calculate_file_sha256(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as fd:
        while True:
            block = fd.read(65536)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()

def server_main(server_host='0.0.0.0', server_port=12345):
    while True:
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server_sock:
                server_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                server_sock.bind((server_host,server_port))
                server_sock.listen()
                print_status(f"Server listening at {server_host}:{server_port}")
                while True:
                    client_sock, client_addr = server_sock.accept()
                    ClientHandler(client_sock, client_addr).start()
        except Exception as exception:
            print_status(f"Server exception: {exception}")
            print_status("Restarting server in 5 seconds...")
            time.sleep(5)

class ClientConnection:
    def __init__(self, server_host, server_port, proxy_host, proxy_port):
        self.server_host = server_host
        self.server_port = server_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.socket = None
        self.aesgcm = None
        self.is_running = False
        self.receive_thread = None
        self.send_thread = None
        self.send_lock = threading.Lock()
        self.pending_messages = {}  # message_id: (encrypted_bytes, last_send_timestamp)
        self.send_queue = Queue()
        self.current_message_id = 0

    def generate_next_message_id(self):
        with self.send_lock:
            self.current_message_id += 1
            return self.current_message_id

    def connect_and_handshake(self):
        try:
            self.socket = socks.socksocket()
            self.socket.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port)
            self.socket.settimeout(10)
            self.socket.connect((self.server_host, self.server_port))
            print_status(f"Connected to server {self.server_host}:{self.server_port}, starting handshake")
            server_pub = self.socket.recv(32)
            if len(server_pub) != 32:
                print_status("Handshake failed: server public key length invalid")
                self.socket.close()
                return False
            server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
            client_private = x25519.X25519PrivateKey.generate()
            client_public = client_private.public_key()
            client_pub_bytes = client_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.socket.sendall(client_pub_bytes)
            shared_secret = client_private.exchange(server_public)
            print_status(f"Handshake shared key (hex first 32 bytes): {shared_secret.hex()[:64]}")
            derived_key = derive_aes_key_with_hkdf(shared_secret)
            print_status(f"HKDF derived AES key (hex first 32 bytes): {derived_key.hex()[:64]}")
            self.aesgcm = AESGCM(derived_key)
            self.socket.settimeout(None)
            return True
        except Exception as exception:
            print_status(f"Connection or handshake error: {exception}")
            if self.socket:
                self.socket.close()
            return False

    def send_encrypted_data(self, encrypted_bytes):
        with self.send_lock:
            message_length = len(encrypted_bytes)
            self.socket.sendall(message_length.to_bytes(4, 'big') + encrypted_bytes)

    def send_loop(self):
        RETRANSMIT_TIMEOUT = 5
        while self.is_running:
            try:
                try:
                    packet_dict = self.send_queue.get(timeout=0.5)
                    message_id = self.generate_next_message_id()
                    packet_dict['message_id'] = message_id
                    plaintext = create_packet(packet_dict['type'], {k:v for k,v in packet_dict.items() if k != 'type'})
                    encrypted_packet = encrypt_message_with_aes_gcm(self.aesgcm, plaintext)
                    self.send_encrypted_data(encrypted_packet)
                    with self.send_lock:
                        self.pending_messages[message_id] = (encrypted_packet, time.time())
                    if packet_dict['type'] == 'text':
                        print_status(f"Sent message id={message_id}: {packet_dict.get('message', '')}")
                    elif packet_dict['type'] == 'file_info':
                        print_status(f"Sent file info id={message_id}")
                    elif packet_dict['type'] == 'file':
                        print_status(f"Sent file chunk id={message_id} index={packet_dict.get('index')}")
                except Empty:
                    pass
                current_time = time.time()
                retransmit_list = []
                with self.send_lock:
                    for msg_id, (edata, last_send_time) in self.pending_messages.items():
                        if current_time - last_send_time > RETRANSMIT_TIMEOUT:
                            retransmit_list.append((msg_id, edata))
                    for msg_id, edata in retransmit_list:
                        print_status(f"Retransmitting message id={msg_id}")
                        self.send_encrypted_data(edata)
                        self.pending_messages[msg_id] = (edata, current_time)
            except Exception as exception:
                print_status(f"Send loop exception: {exception}")
                self.is_running = False
                break

    def handle_acknowledgement(self, ack_id):
        with self.send_lock:
            if ack_id in self.pending_messages:
                print_status(f"Received ACK id={ack_id}, removing from pending")
                del self.pending_messages[ack_id]

    def receive_loop(self):
        while self.is_running:
            try:
                header_bytes = self.socket.recv(4)
                if not header_bytes or len(header_bytes) < 4:
                    print_status("Server closed or failed to read length")
                    self.is_running = False
                    break
                packet_length = int.from_bytes(header_bytes, 'big')
                if packet_length <= 0:
                    print_status("Invalid packet length received")
                    self.is_running = False
                    break
                received_data = b''
                while len(received_data) < packet_length:
                    chunk = self.socket.recv(packet_length - len(received_data))
                    if not chunk:
                        break
                    received_data += chunk
                if len(received_data) < packet_length:
                    print_status("Incomplete packet received")
                    self.is_running = False
                    break
                decrypted_plaintext = decrypt_message_with_aes_gcm(self.aesgcm, received_data)
                if decrypted_plaintext is None:
                    print_status("Failed to decrypt packet; ignoring")
                    continue
                parsed_packet = parse_packet_from_bytes(decrypted_plaintext.encode('utf-8'))
                if not parsed_packet or 'type' not in parsed_packet:
                    print_status("Packet format invalid; ignoring")
                    continue
                packet_type = parsed_packet['type']
                if packet_type == 'ack':
                    ack_id = parsed_packet.get('ack_id')
                    if ack_id:
                        self.handle_acknowledgement(ack_id)
                else:
                    message_id = parsed_packet.get('message_id')
                    if message_id:
                        ack_packet_dict = create_packet('ack', {'ack_id': message_id})
                        encrypted_ack_packet = encrypt_message_with_aes_gcm(self.aesgcm, ack_packet_dict)
                        self.send_encrypted_data(encrypted_ack_packet)
                    if packet_type == 'text':
                        print(f"\r[{get_current_time_string()}][Server]: {parsed_packet.get('message', '')}\n>>> ", end='')
                    else:
                        print_status(f"Unsupported message type: {packet_type}")
            except Exception as exception:
                print_status(f"Receive loop exception: {exception}")
                self.is_running = False
                break

    def start(self):
        while True:
            if self.connect_and_handshake():
                self.is_running = True
                self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
                self.send_thread = threading.Thread(target=self.send_loop, daemon=True)
                self.receive_thread.start()
                self.send_thread.start()
                self.receive_thread.join()
                self.send_thread.join()
            else:
                print_status("Connection failed, retrying in 5 seconds...")
                time.sleep(5)

def print_choose_mode_prompt():
    print("Choose mode:")
    print("1 - Run as server")
    print("2 - Run as client")
    print("3 - Quit")

def main():
    DEFAULT_SERVER_HOST = '0.0.0.0'
    DEFAULT_SERVER_PORT = 12345

    while True:
        print_choose_mode_prompt()
        user_choice = input("Enter mode number and hit Enter: ").strip()
        if user_choice == '1':
            print_status("Starting server mode...")
            server_main(DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT)
        elif user_choice == '2':
            server_ip = input("Enter server IP to connect: ").strip()
            try:
                server_port = int(input("Enter server port (default 12345): ").strip())
            except:
                server_port = 12345
            proxy_ip = input("Enter SOCKS5 proxy IP (default 127.0.0.1): ").strip() or "127.0.0.1"
            try:
                proxy_port = int(input("Enter SOCKS5 proxy port (default 1080): ").strip())
            except:
                proxy_port = 1080
            print_status("Starting client mode...")
            client = ClientConnection(server_ip, server_port, proxy_ip, proxy_port)
            print_status("Client commands:\n  /sendfile <filepath> - send file\n  exit - quit")
            client.start()
        elif user_choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again")

if __name__ == '__main__':
    main()
