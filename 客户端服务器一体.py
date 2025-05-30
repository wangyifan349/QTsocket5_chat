import socket
import threading
import struct
import os
import sys

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# -------------------------------------------------------------------------
# 通用数据收发辅助函数
# -------------------------------------------------------------------------

def send_msg(sock: socket.socket, data: bytes):
    """
    发送数据前先发送4字节长度，再发送数据本体，防止粘包
    """
    try:
        sock.sendall(struct.pack('!I', len(data)))
        sock.sendall(data)
    except Exception as e:
        print(f"[send_msg] Exception: {e}")

def recvall(sock: socket.socket, n: int):
    """
    接收n字节数据，确保接收完整，不足或连接关闭返回None
    """
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        except Exception as e:
            print(f"[recvall] Exception: {e}")
            return None
    return data

def recv_msg(sock: socket.socket):
    """
    先接收4字节数据长度，再接收对应长度的消息内容
    """
    try:
        raw_len = recvall(sock, 4)
        if not raw_len:
            return None
        msg_len = struct.unpack('!I', raw_len)[0]
        return recvall(sock, msg_len)
    except Exception as e:
        print(f"[recv_msg] Exception: {e}")
        return None

# -------------------------------------------------------------------------
# AES-GCM 加密 / 解密，使用 PyCryptodome
# 数据格式为：nonce(12 bytes) + tag(16 bytes) + 密文
# -------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = get_random_bytes(12)  # GCM推荐12字节随机数
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext

def aes_gcm_decrypt(key: bytes, data: bytes) -> bytes or None:
    try:
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        print(f"[aes_gcm_decrypt] 认证失败或数据异常: {e}")
        return None
    except Exception as e:
        print(f"[aes_gcm_decrypt] 异常: {e}")
        return None

# -------------------------------------------------------------------------
# 使用 X25519 生成共享密钥并用 HKDF 派生 AES 密钥
# -------------------------------------------------------------------------

def derive_aes_key(shared_key: bytes, length=32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'handshake data',
    )
    return hkdf.derive(shared_key)

# -------------------------------------------------------------------------
# 线程基类和发送/接收线程实现，确保线程安全和异常处理
# -------------------------------------------------------------------------

class SafeSocketThread(threading.Thread):
    def __init__(self, sock, aes_key, role=""):
        super().__init__()
        self.sock = sock
        self.aes_key = aes_key
        self.role = role
        self.daemon = True
        self.running = True

    def stop(self):
        self.running = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except:
            pass

class Receiver(SafeSocketThread):
    def run(self):
        while self.running:
            data = recv_msg(self.sock)
            if data is None:
                print(f"[{self.role}] 连接关闭或接收失败，退出接收线程")
                break
            plaintext = aes_gcm_decrypt(self.aes_key, data)
            if plaintext is not None:
                print(f"[{self.role} 接收]: {plaintext.decode(errors='ignore')}")
        self.stop()

class Sender(SafeSocketThread):
    def run(self):
        while self.running:
            try:
                text = input()
                if text.lower() == "exit":
                    print(f"[{self.role}] 用户请求退出，关闭发送线程")
                    self.stop()
                    break
                encrypted = aes_gcm_encrypt(self.aes_key, text.encode())
                send_msg(self.sock, encrypted)
            except Exception as e:
                print(f"[{self.role} 发送异常: {e}，退出发送线程")
                self.stop()
                break

# -------------------------------------------------------------------------
# TCP服务端实现
# -------------------------------------------------------------------------

def server(host='127.0.0.1', port=65432):
    print("[服务器] 启动...")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(1)
    print(f"[服务器] 监听 {host}:{port}")

    try:
        conn, addr = listener.accept()
        print(f"[服务器] 建立连接 - 来自 {addr}")

        # 生成服务端X25519密钥对，先发送公钥给客户端
        server_priv = x25519.X25519PrivateKey.generate()
        server_pub = server_priv.public_key()
        send_msg(conn, server_pub.public_bytes())

        # 接收客户端公钥
        client_pub_raw = recv_msg(conn)
        if client_pub_raw is None:
            print("[服务器] 未收到客户端公钥，断开连接")
            conn.close()
            return
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_raw)

        # 计算共享密钥并派生AES对称密钥
        shared_key = server_priv.exchange(client_pub)
        aes_key = derive_aes_key(shared_key)
        print("[服务器] AES共享密钥协商完成")

        # 创建发送和接收线程，保证异步通信
        receiver = Receiver(conn, aes_key, role="服务器")
        sender = Sender(conn, aes_key, role="服务器")
        receiver.start()
        sender.start()

        receiver.join()  # 等待接收线程退出
        sender.running = False  # 告知发送线程退出（通常用户输入exit结束）

    except Exception as e:
        print(f"[服务器] 异常: {e}")
    finally:
        listener.close()
        print("[服务器] 已关闭")

# -------------------------------------------------------------------------
# TCP客户端实现
# -------------------------------------------------------------------------

def client(host='127.0.0.1', port=65432):
    print("[客户端] 启动...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print("[客户端] 连接服务器成功")

        # 接收服务器公钥
        server_pub_raw = recv_msg(sock)
        if server_pub_raw is None:
            print("[客户端] 未收到服务器公钥，关闭连接")
            sock.close()
            return
        server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_raw)

        # 生成客户端X25519密钥对，发送公钥
        client_priv = x25519.X25519PrivateKey.generate()
        client_pub = client_priv.public_key()
        send_msg(sock, client_pub.public_bytes())

        # 计算共享密钥并派生AES密钥
        shared_key = client_priv.exchange(server_pub)
        aes_key = derive_aes_key(shared_key)
        print("[客户端] AES共享密钥协商完成")

        # 启动发送和接收线程
        receiver = Receiver(sock, aes_key, role="客户端")
        sender = Sender(sock, aes_key, role="客户端")
        receiver.start()
        sender.start()

        receiver.join()
        sender.running = False

    except Exception as e:
        print(f"[客户端] 异常: {e}")
    finally:
        sock.close()
        print("[客户端] 已关闭连接")

# -------------------------------------------------------------------------
# 主程序入口，根据命令行参数启动服务器或客户端
# -------------------------------------------------------------------------

if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('server', 'client'):
        print(f"用法: python {sys.argv[0]} server|client")
        sys.exit(1)

    if sys.argv[1] == 'server':
        server()
    else:
        client()
