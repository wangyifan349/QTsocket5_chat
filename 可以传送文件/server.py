import socket
import threading
import json
import base64
import os
import math
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '0.0.0.0'               # 监听所有网卡
PORT = 12345                  # 监听端口

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")   # 当前时间格式化

def make_packet(type_, payload: dict):
    packet = {'type': type_}       # JSON消息结构加类型字段
    packet.update(payload)
    return json.dumps(packet).encode('utf-8')     # 转成json字符串，编码utf8返回

def parse_packet(data_bytes):
    try:
        return json.loads(data_bytes.decode('utf-8'))   # 解析json，失败返回None
    except:
        return None

def encrypt_message(aesgcm, plaintext: str):
    nonce = os.urandom(12)          # 生成12字节随机nonce（AES-GCM推荐长度）
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None) # 加密
    packet = {
        'nonce': base64.b64encode(nonce).decode('utf-8'),      # nonce base64编码
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')  # 密文base64编码
    }
    return json.dumps(packet).encode('utf-8')   # 打包成json，utf8编码发送

def decrypt_message(aesgcm, data: bytes):
    try:
        packet = json.loads(data.decode('utf-8'))     # 解析json包
        nonce = base64.b64decode(packet['nonce'])      # base64解nonce
        ciphertext = base64.b64decode(packet['ciphertext'])    # base64解密文
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)    # AES-GCM解密
        return plaintext.decode('utf-8')             # 转utf8字符串
    except Exception as e:
        print(f"{now_str()} 解密消息异常: {e}")          # 解密异常打印
        return None

def derive_key_iterated(shared_key: bytes, iterations=1000, length=32) -> bytes:
    # 採用HKDF迭代形式，增强共享密钥安全
    key_material = shared_key
    for _ in range(iterations):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),          # 哈希算法SHA256
            length=length,                     # 派生出length长度字节
            salt=None,                        # 不使用salt
            info=b'chat app derived key',    # 应用info
        )
        key_material = hkdf.derive(key_material)   # 派生密钥，重复迭代
    return key_material

def x25519_handshake(conn):
    server_private = x25519.X25519PrivateKey.generate()    # 生成服务器X25519私钥
    server_public = server_private.public_key()           # 获得公钥
    server_pub_bytes = server_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    try:
        conn.sendall(server_pub_bytes)                      # 发送服务器公钥32字节
        client_pub_bytes = conn.recv(32)                    # 接收客户端公钥
        if len(client_pub_bytes) != 32:                     # 检查长度
            print(f"{now_str()} 握手失败，客户端公钥长度错误")
            return None
        client_public = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)  # 构造客户端公钥对象
        shared = server_private.exchange(client_public)     # 计算共享密钥
        derived_key = derive_key_iterated(shared, iterations=1000)  # 迭代派生密钥
        print(f"{now_str()} 握手完成，共享密钥(HEX)[前32B]: {derived_key.hex()[:64]}")   
        return AESGCM(derived_key)                           # 返回AESGCM加密对象
    except Exception as e:
        print(f"{now_str()} 握手异常: {e}")
        return None

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.aesgcm = None
        self.running = True

    def run(self):
        print(f"{now_str()} 新客户端连接: {self.addr}")
        self.aesgcm = x25519_handshake(self.conn)   # 握手协商密钥
        if not self.aesgcm:
            print(f"{now_str()} 握手失败，关闭连接")
            self.conn.close()
            return
        try:
            self.recv_loop()     # 进入接收循环
        except Exception as e:
            print(f"{now_str()} 连接异常 {self.addr}: {e}")
        finally:
            self.conn.close()
            print(f"{now_str()} 连接关闭 {self.addr}")

    def recv_loop(self):
        while self.running:
            header = self.conn.recv(4)              # 读4字节消息长度
            if not header or len(header) < 4:
                print(f"{now_str()} {self.addr} 断开或读取长度失败")
                break
            length = int.from_bytes(header, 'big') # 转整数包长度
            if length <= 0:
                print(f"{now_str()} {self.addr} 错误数据长度")
                break
            data = b''
            while len(data) < length:               # 循环确保读满数据
                chunk = self.conn.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) < length:
                print(f"{now_str()} {self.addr} 数据包不完整，断开")
                break
            plaintext = decrypt_message(self.aesgcm, data)    # 解密
            if plaintext is not None:
                print(f"[{now_str()}][{self.addr}]: {plaintext}")
            else:
                print(f"{now_str()} 解密失败，丢弃数据包")

def server_main():
    import time
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # 重用地址
                server.bind((HOST, PORT))
                server.listen()
                print(f"{now_str()} 服务器监听 {HOST}:{PORT}")
                while True:
                    conn, addr = server.accept()    # 阻塞等连接
                    handler = ClientHandler(conn, addr)
                    handler.start()                # 新线程处理连接
        except Exception as e:
            print(f"{now_str()} 服务器异常: {e}")
            print(f"{now_str()} 5秒后重启监听...")
            time.sleep(5)

if __name__ == '__main__':
    server_main()
