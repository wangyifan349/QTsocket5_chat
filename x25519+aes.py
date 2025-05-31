#!/usr/bin/env python3
import socket
import threading
import struct
import sys
import os
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------------------------------------------------------
# 通用数据收发辅助函数，不受异常影响，防止粘包
# -------------------------------------------------------------------------
def send_msg(sock: socket.socket, data: bytes):
    """
    发送数据前先发送4字节长度，再发送数据本体
    """
    try:
        sock.sendall(struct.pack('!I', len(data)))
        sock.sendall(data)
    except Exception as e:
        print(f"[send_msg] Exception: {e}")
def recvall(sock: socket.socket, n: int):
    """
    接收n字节数据，确保接收完整；若不足或连接关闭返回None
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
    先接收4字节数据长度，再接收对应长度的数据
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
# 对称加解密函数（使用 AES-GCM）
# -------------------------------------------------------------------------
def derive_symmetric_key(shared_key: bytes) -> bytes:
    """
    通过 HKDF 从共享秘钥中派生出 32 字节对称秘钥
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    )
    return hkdf.derive(shared_key)
def aes_encrypt(aes_key: bytes, plaintext: bytes) -> bytes:
    """
    使用 AES-GCM 加密，随机生成 12 字节 nonce，并返回 nonce + ciphertext
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext
def aes_decrypt(aes_key: bytes, data: bytes) -> bytes:
    """
    前12字节为 nonce，其余为 ciphertext，使用 AES-GCM 解密
    """
    if len(data) < 12:
        raise ValueError("数据长度太短，无法提取 nonce")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
# -------------------------------------------------------------------------
# 密钥交换函数，打印交换过程中的中间信息（仅调试用）
# -------------------------------------------------------------------------
def perform_key_exchange_initiator(sock: socket.socket) -> bytes:
    """
    initiator（主动方）：
      1. 生成临时 X25519 秘钥对，并打印公钥
      2. 先发送自己的公钥，再接收对方公钥
      3. 利用 X25519 计算共享密钥
      4. 使用 HKDF 派生出 AES 对称秘钥
    """
    my_private_key = x25519.X25519PrivateKey.generate()
    my_public_key = my_private_key.public_key()
    my_pub_bytes = my_public_key.public_bytes()  # 默认返回原始字节
    print(f"[Key Exchange] Initiator 公钥: {my_pub_bytes.hex()}")
    
    # 先发送自己的公钥
    send_msg(sock, my_pub_bytes)
    # 接收对方公钥
    peer_pubkey_bytes = recv_msg(sock)
    if not peer_pubkey_bytes:
        raise ValueError("未能收到对方公钥！")
    print(f"[Key Exchange] 从对方收到公钥: {peer_pubkey_bytes.hex()}")
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pubkey_bytes)
    shared_key = my_private_key.exchange(peer_public_key)
    print(f"[Key Exchange] 计算共享密钥: {shared_key.hex()}")
    aes_key = derive_symmetric_key(shared_key)
    print(f"[Key Exchange] 派生出对称 AES 秘钥: {aes_key.hex()}")
    return aes_key
def perform_key_exchange_responder(sock: socket.socket) -> bytes:
    """
    responder（应答方）：
      1. 生成临时 X25519 秘钥对，并打印公钥
      2. 先接收对方公钥，再发送自己的公钥
      3. 利用 X25519 计算共享密钥
      4. 使用 HKDF 派生出 AES 对称秘钥
    """
    my_private_key = x25519.X25519PrivateKey.generate()
    my_public_key = my_private_key.public_key()
    my_pub_bytes = my_public_key.public_bytes()
    # 先接收对方公钥
    peer_pubkey_bytes = recv_msg(sock)
    if not peer_pubkey_bytes:
        raise ValueError("未能收到对方公钥！")
    print(f"[Key Exchange] 从对方收到公钥: {peer_pubkey_bytes.hex()}")
    # 发送自己的公钥
    send_msg(sock, my_pub_bytes)
    print(f"[Key Exchange] Responder 公钥: {my_pub_bytes.hex()}")
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pubkey_bytes)
    shared_key = my_private_key.exchange(peer_public_key)
    print(f"[Key Exchange] 计算共享密钥: {shared_key.hex()}")
    aes_key = derive_symmetric_key(shared_key)
    print(f"[Key Exchange] 派生出对称 AES 秘钥: {aes_key.hex()}")
    return aes_key

# -------------------------------------------------------------------------
# 线程基类及发送/接收线程实现（异常处理独立，互不干扰）
# -------------------------------------------------------------------------
class SafeSocketThread(threading.Thread):
    def __init__(self, sock: socket.socket, aes_key: bytes, role=""):
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
        except Exception as e:
            pass
        finally:
            try:
                self.sock.close()
            except Exception as e:
                pass

class Receiver(SafeSocketThread):
    def run(self):
        print("[Receiver] 启动接收线程，等待数据...")
        while self.running:
            try:
                data = recv_msg(self.sock)
                if data is None:
                    print("[Receiver] 未收到数据或连接中断。")
                    time.sleep(0.5)
                    continue
                try:
                    plaintext = aes_decrypt(self.aes_key, data)
                    print(f"[Receiver] 收到消息：{plaintext.decode('utf-8', errors='replace')}")
                except Exception as de:
                    print(f"[Receiver] 解密失败：{de}")
            except Exception as e:
                print(f"[Receiver] Exception: {e}")
            # 避免 CPU 占用过高
            time.sleep(0.1)
        print("[Receiver] 线程退出。")
        self.stop()

class Sender(SafeSocketThread):
    def run(self):
        print("[Sender] 启动发送线程，输入 exit 退出。")
        while self.running:
            try:
                text = input()
                if text.lower() == 'exit':
                    print("[Sender] 检测到退出命令，发送线程退出。")
                    self.running = False
                    break
                plaintext = text.encode('utf-8')
                try:
                    encrypted_data = aes_encrypt(self.aes_key, plaintext)
                    send_msg(self.sock, encrypted_data)
                except Exception as se:
                    print(f"[Sender] 加密或发送失败：{se}")
            except Exception as e:
                print(f"[Sender] Exception: {e}")
            # 避免 CPU 占用过高
            time.sleep(0.1)
        print("[Sender] 线程退出。")
        self.stop()
# -------------------------------------------------------------------------
# 服务端与客户端逻辑
# -------------------------------------------------------------------------
def run_server(bind_ip: str, bind_port: int):
    print("[Server] 启动服务器...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bind_ip, bind_port))
    server.listen(5)
    print(f"[Server] 正在监听 {bind_ip}:{bind_port} ...")
    client_sock, addr = server.accept()
    print(f"[Server] 接收到客户端连接：{addr}")
    try:
        # 本端为 responder（应答方）
        aes_key = perform_key_exchange_responder(client_sock)
    except Exception as e:
        print(f"[Server] 密钥交换失败：{e}")
        client_sock.close()
        server.close()
        return

    # 启动发送和接收线程（互不干扰）
    recv_thread = Receiver(client_sock, aes_key=aes_key, role="Receiver")
    send_thread = Sender(client_sock, aes_key=aes_key, role="Sender")
    recv_thread.start()
    send_thread.start()

    # 主线程等待两线程结束
    recv_thread.join()
    send_thread.join()
    server.close()
    print("[Server] 服务器程序退出。")
def run_client(server_ip: str, server_port: int):
    print("[Client] 尝试连接服务器...")
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((server_ip, server_port))
    print("[Client] 连接成功。")    
    try:
        # 本端为 initiator（主动方）
        aes_key = perform_key_exchange_initiator(client_sock)
    except Exception as e:
        print(f"[Client] 密钥交换失败：{e}")
        client_sock.close()
        return

    # 启动发送和接收线程
    recv_thread = Receiver(client_sock, aes_key=aes_key, role="Receiver")
    send_thread = Sender(client_sock, aes_key=aes_key, role="Sender")
    recv_thread.start()
    send_thread.start()

    recv_thread.join()
    send_thread.join()
    client_sock.close()
    print("[Client] 客户端程序退出。")

def print_usage():
    print("用法：")
    print("  作为服务器: python3 this_script.py server [bind_ip] [bind_port]")
    print("  作为客户端: python3 this_script.py client [server_ip] [server_port]")
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print_usage()

    mode = sys.argv[1].lower()
    if mode == "server":
        bind_ip = sys.argv[2]
        try:
            bind_port = int(sys.argv[3])
        except ValueError:
            print("无效端口号")
            sys.exit(1)
        run_server(bind_ip, bind_port)
    elif mode == "client":
        server_ip = sys.argv[2]
        try:
            server_port = int(sys.argv[3])
        except ValueError:
            print("无效端口号")
            sys.exit(1)
        run_client(server_ip, server_port)
    else:
        print_usage()
