import socks
import threading
import json
import base64
import os
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = '服务器IP'   # 请改实际地址
SERVER_PORT = 12345

PROXY_HOST = '代理IP'      # 请改代理IP
PROXY_PORT = 1080

RECONNECT_DELAY = 5       # 重连间隔秒数

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def make_packet(type_, payload: dict):
    packet = {'type': type_}
    packet.update(payload)
    return json.dumps(packet).encode('utf-8')

def parse_packet(data_bytes):
    try:
        return json.loads(data_bytes.decode('utf-8'))
    except:
        return None

def encrypt_message(aesgcm, plaintext: str):
    nonce = os.urandom(12)                      # 生成12字节随机nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)   # AES-GCM加密
    packet = {
        'nonce': base64.b64encode(nonce).decode('utf-8'),               # nonce base64
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')      # 密文 base64
    }
    return json.dumps(packet).encode('utf-8')        # 转json字符串utf8编码

def decrypt_message(aesgcm, data: bytes):
    try:
        packet = json.loads(data.decode('utf-8'))      # 解析json
        nonce = base64.b64decode(packet['nonce'])       # 解码nonce
        ciphertext = base64.b64decode(packet['ciphertext'])  # 解码密文
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)  # AES-GCM解密
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"{now_str()} 解密消息异常: {e}")
        return None

def derive_key_iterated(shared_key: bytes, iterations=1000, length=32) -> bytes:
    key_material = shared_key
    for _ in range(iterations):                        # 迭代1000次HKDF派生
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b'chat app derived key',
        )
        key_material = hkdf.derive(key_material)
    return key_material

class ClientConnection:
    def __init__(self):
        self.sock = None
        self.aesgcm = None
        self.running = False
        self.recv_thread = None
        self.send_thread = None

    def connect_and_handshake(self):
        self.sock = socks.socksocket()            # SOCKS5代理socket
        self.sock.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
        self.sock.settimeout(10)
        try:
            self.sock.connect((SERVER_HOST, SERVER_PORT))         # 连接服务器
            print(f"{now_str()} 已连接服务器，开始握手...")
            server_pub = self.sock.recv(32)                        # 接收服务器公钥
            if len(server_pub) != 32:
                print(f"{now_str()} 握手失败，服务器公钥长度错误")
                self.sock.close()
                return False
            server_public_key = x25519.X25519PublicKey.from_public_bytes(server_pub)
            client_private_key = x25519.X25519PrivateKey.generate()
            client_public_key = client_private_key.public_key()
            client_pub_bytes = client_public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
            self.sock.sendall(client_pub_bytes)                    # 发送客户端公钥

            shared = client_private_key.exchange(server_public_key)  # 计算共享密钥
            derived_key = derive_key_iterated(shared, iterations=1000)  # 迭代派生32字节对称密钥
            self.aesgcm = AESGCM(derived_key)
            print(f"{now_str()} 握手成功，AES密钥派生完成")
            self.sock.settimeout(None)
            return True
        except Exception as e:
            print(f"{now_str()} 连接/握手异常: {e}")
            if self.sock:
                self.sock.close()
            return False

    def recv_loop(self):
        try:
            while self.running:
                header = self.sock.recv(4)               # 读包长度4字节
                if not header or len(header) < 4:
                    print(f"{now_str()} 服务器关闭或读取长度失败")
                    break
                length = int.from_bytes(header, 'big')
                if length <= 0:
                    print(f"{now_str()} 异常数据包长度")
                    break
                data = b''
                while len(data) < length:
                    chunk = self.sock.recv(length - len(data))    # 读满包内容
                    if not chunk:
                        break
                    data += chunk
                if len(data) < length:
                    print(f"{now_str()} 收包不完整")
                    break
                plaintext = decrypt_message(self.aesgcm, data)      # 解密消息
                if plaintext:
                    print(f"\r{plaintext}\n>>> ", end='')
        except Exception as e:
            print(f"{now_str()} 接收线程异常: {e}")
        self.running = False

    def send_loop(self):
        try:
            while self.running:
                msg = input(">>> ").strip()
                if msg.lower() == "exit":
                    print(f"{now_str()} 主动断开连接")
                    self.running = False
                    self.sock.close()
                    break
                full_msg = f"[{now_str()}] {msg}"
                packet = make_packet('text', {'message': full_msg})
                ciphertext = encrypt_message(self.aesgcm, packet.decode('utf-8'))
                self.sock.sendall(len(ciphertext).to_bytes(4, 'big') + ciphertext)   # 先发长度，再发包体
                print(f"{now_str()} [我发送]: {full_msg}")
        except Exception as e:
            print(f"{now_str()} 发送线程异常: {e}")
        self.running = False

    def start(self):
        while True:
            if self.connect_and_handshake():
                self.running = True
                self.recv_thread = threading.Thread(target=self.recv_loop, daemon=True)  # 接收线程
                self.send_thread = threading.Thread(target=self.send_loop, daemon=True)  # 发送线程
                self.recv_thread.start()
                self.send_thread.start()
                self.recv_thread.join()
                self.send_thread.join()
            else:
                print(f"{now_str()} 连接失败，等待{RECONNECT_DELAY}s后重试...")
                time.sleep(RECONNECT_DELAY)

if __name__ == '__main__':
    client = ClientConnection()
    client.start()
