────────────────────────────  
server.py  
────────────────────────────
#!/usr/bin/env python3
import socket
import threading
import struct
import os
import json
import time

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError

# ------------------------------
# 简单的 HKDF 派生函数，用于从共享密钥中导出 AES 密钥
# ------------------------------
def hkdf_derive(key_material, salt=b"handshake salt", info=b"AES key"):
    h = HMAC.new(salt, digestmod=SHA256)
    h.update(key_material)
    prk = h.digest()  # pseudorandom key
    h2 = HMAC.new(prk, digestmod=SHA256)
    h2.update(info + b"\x01")
    return h2.digest()  # 输出 32 字节密钥
# ------------------------------
# 将数据打包：先传输4字节长度，再传输 JSON 数据
# ------------------------------
def send_packet(conn, data: str):
    encoded = data.encode()
    packet_length = struct.pack(">I", len(encoded))
    conn.sendall(packet_length + encoded)
# ------------------------------
# 接收完整数据包（先接收4字节长度，再收到对应数据）
# ------------------------------
def recv_packet(conn):
    header = recv_all(conn, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    data = recv_all(conn, length)
    if data is None:
        return None
    return data.decode()

def recv_all(conn, n):
    data = b""
    while len(data) < n:
        try:
            packet = conn.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data += packet
    return data
# ------------------------------
# 全局变量：AES 密钥，用于加解密
# ------------------------------
aes_key = None
# ------------------------------
# 握手过程：使用 X25519 进行密钥交换，并通过 HKDF 派生 AES 密钥
# ------------------------------
def handshake(conn, is_server=True):
    global aes_key
    try:
        # 生成 X25519 密钥对（使用 PyNaCl 实现）
        my_private = PrivateKey.generate()
        my_public = my_private.public_key
        # 公钥交换流程
        if is_server:
            # 服务器等待客户端发送公钥，再发送自己的公钥
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("未收到客户端公钥")
            peer_pub = json.loads(peer_pub_json)["pub"]
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
        else:
            # 客户端先发送公钥，再等待服务器回复
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("未收到服务器公钥")
            peer_pub = json.loads(peer_pub_json)["pub"]
        # 将对方公钥转换成 PublicKey 对象
        peer_public = PublicKey(bytes.fromhex(peer_pub))
        # 计算共享密钥
        shared = my_private.exchange(peer_public)
        aes_key = hkdf_derive(shared)
        print("[握手成功] 共享 AES key：", aes_key.hex())
        return True
    except Exception as e:
        print("[握手异常]:", e)
        return False
# ------------------------------
# 加密消息，返回 JSON 格式字符串
# JSON 中包括 nonce、tag、ciphertext(均转16进制字符串)
# ------------------------------
def encrypt_message(plaintext: bytes) -> str:
    # 生成随机 nonce（12 字节）用于 AES-GCM
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = {
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    return json.dumps(payload)
# ------------------------------
# 解密 JSON 格式数据，返回明文 bytes
# ------------------------------
def decrypt_message(json_data: str) -> bytes:
    try:
        data = json.loads(json_data)
        nonce = bytes.fromhex(data["nonce"])
        tag = bytes.fromhex(data["tag"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError, CryptoError) as e:
        raise ValueError("解密或数据格式错误: " + str(e))
# ------------------------------
# 发送线程：循环读取用户输入进行加密并发送
# ------------------------------
def send_thread(conn):
    while True:
        try:
            msg = input()
            if not msg:
                continue
            # 加密消息
            encrypted_json = encrypt_message(msg.encode())
            send_packet(conn, encrypted_json)
        except Exception as e:
            print("[发送异常]:", e)
            break
# ------------------------------
# 接收线程：循环接收数据包，解密后打印消息
# ------------------------------
def recv_thread(conn):
    while True:
        try:
            data_json = recv_packet(conn)
            if data_json is None:
                print("[连接断开] 尝试重连...")
                break
            plaintext = decrypt_message(data_json)
            print("\n[收到]:", plaintext.decode())
        except (ValueError, CryptoError) as e:
            print("[解密错误]:", e)
        except Exception as e:
            print("[接收异常]:", e)
            break
# ------------------------------
# 主函数：监听连接，遇断线则重连（重新握手）
# ------------------------------
def main():
    host = "0.0.0.0"
    port = 9999
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    print("[服务器启动] 等待连接...")
    while True:
        try:
            conn, addr = server_sock.accept()
            print("[连接建立] 来自：", addr)
            if not handshake(conn, is_server=True):
                conn.close()
                continue
            # 同时启用发送和接收线程
            t_send = threading.Thread(target=send_thread, args=(conn,))
            t_recv = threading.Thread(target=recv_thread, args=(conn,))
            t_send.start()
            t_recv.start()
            t_send.join()
            t_recv.join()
            print("[会话结束] 断开连接，等待重连...")
            conn.close()
        except Exception as e:
            print("[主循环异常]:", e)
        # 间隔后继续等待新的连接
        time.sleep(2)
if __name__ == "__main__":
    main()










────────────────────────────  
client.py  
────────────────────────────
#!/usr/bin/env python3
import socket
import threading
import struct
import os
import json
import time
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
# ------------------------------
# 使用 HKDF 派生 AES 密钥
# ------------------------------
def hkdf_derive(key_material, salt=b"handshake salt", info=b"AES key"):
    h = HMAC.new(salt, digestmod=SHA256)
    h.update(key_material)
    prk = h.digest()
    h2 = HMAC.new(prk, digestmod=SHA256)
    h2.update(info + b"\x01")
    return h2.digest()
# ------------------------------
# 将数据打包：先传4字节长度，再发送 JSON 数据
# ------------------------------
def send_packet(conn, data: str):
    encoded = data.encode()
    packet_length = struct.pack(">I", len(encoded))
    conn.sendall(packet_length + encoded)
# ------------------------------
# 接收数据包（先接收长度，再接收 JSON 数据）
# ------------------------------
def recv_packet(conn):
    header = recv_all(conn, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    data = recv_all(conn, length)
    if data is None:
        return None
    return data.decode()

def recv_all(conn, n):
    data = b""
    while len(data) < n:
        try:
            packet = conn.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data += packet
    return data
# ------------------------------
# 全局变量：AES 密钥
# ------------------------------
aes_key = None
# ------------------------------
# 握手过程：使用 X25519 完成密钥交换及 AES 密钥派生
# ------------------------------
def handshake(conn, is_server=False):
    global aes_key
    try:
        my_private = PrivateKey.generate()
        my_public = my_private.public_key
        if is_server:
            # 服务器模式
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("未收到对方公钥")
            peer_pub = json.loads(peer_pub_json)["pub"]
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
        else:
            # 客户端模式先发送公钥，再等待回复
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("未收到对方公钥")
            peer_pub = json.loads(peer_pub_json)["pub"]
        peer_public = PublicKey(bytes.fromhex(peer_pub))
        shared = my_private.exchange(peer_public)
        aes_key = hkdf_derive(shared)
        print("[握手成功] 共享 AES key：", aes_key.hex())
        return True
    except Exception as e:
        print("[握手异常]:", e)
        return False

# ------------------------------
# 加密消息：使用 AES-GCM 加密后构造 JSON 对象（nonce, tag, ciphertext均为16进制）
# ------------------------------
def encrypt_message(plaintext: bytes) -> str:
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = {
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    return json.dumps(payload)
# ------------------------------
# 解密函数：解析 JSON 格式消息并解密
# ------------------------------
def decrypt_message(json_data: str) -> bytes:
    try:
        data = json.loads(json_data)
        nonce = bytes.fromhex(data["nonce"])
        tag = bytes.fromhex(data["tag"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError, CryptoError) as e:
        raise ValueError("解密或数据格式错误: " + str(e))
# ------------------------------
# 发送线程：循环等待用户输入，若网络异常则尝试退出线程
# ------------------------------
def send_thread(conn):
    while True:
        try:
            msg = input()
            if not msg:
                continue
            encrypted_json = encrypt_message(msg.encode())
            send_packet(conn, encrypted_json)
        except Exception as e:
            print("[发送异常]:", e)
            break
# ------------------------------
# 接收线程：循环接收数据，异常中断时退出
# ------------------------------
def recv_thread(conn):
    while True:
        try:
            data_json = recv_packet(conn)
            if data_json is None:
                print("[连接断开] 尝试重连...")
                break
            plaintext = decrypt_message(data_json)
            print("\n[收到]:", plaintext.decode())
        except (ValueError, CryptoError) as e:
            print("[解密错误]:", e)
        except Exception as e:
            print("[接收异常]:", e)
            break
# ------------------------------
# 客户端主循环：建立连接，并在连接断开时尝试自动重连
# ------------------------------
def main():
    host = "127.0.0.1"  # 修改为服务器地址
    port = 9999
    while True:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("[连接中] 尝试连接到 {}:{}".format(host, port))
            conn.connect((host, port))
            print("[连接成功] 与服务器建立连接")
            if not handshake(conn, is_server=False):
                conn.close()
                time.sleep(2)
                continue
            # 启动发送与接收线程
            t_send = threading.Thread(target=send_thread, args=(conn,))
            t_recv = threading.Thread(target=recv_thread, args=(conn,))
            t_send.start()
            t_recv.start()
            t_send.join()
            t_recv.join()
            conn.close()
            print("[会话结束] 断开连接，等待重连...")
        except Exception as e:
            print("[连接异常]:", e)
        # 断线后延迟后重连
        time.sleep(2)
if __name__ == "__main__":
    main()
