#!/usr/bin/env python3
import socket
import threading
import struct
import sys
import os
import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import x25519

# -------------------------------------------------------------------------
# 辅助函数：发送和接收带长度前缀的数据，防止粘包
# -------------------------------------------------------------------------
def send_msg(sock, data):
    try:
        length_prefix = struct.pack('!I', len(data))
        sock.sendall(length_prefix)
        sock.sendall(data)
    except Exception as e:
        print("[send_msg] exception:", e)

def recvall(sock, n):
    data = b''
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
            if not packet:
                # 连接关闭
                return None
            data += packet
        except Exception as e:
            print("[recvall] exception:", e)
            return None
    return data

def recv_msg(sock):
    raw_len = recvall(sock, 4)
    if raw_len is None:
        return None
    msg_len = struct.unpack('!I', raw_len)[0]
    return recvall(sock, msg_len)

# -------------------------------------------------------------------------
# 对称加密：AES-GCM 加密解密（先校验TAG）
# -------------------------------------------------------------------------

# AES-GCM包装加密，返回 nonce + ciphertext + tag
def aes_encrypt(key, plaintext):
    try:
        nonce = get_random_bytes(12)  # 96 bits nonce
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ciphertext + tag
    except Exception as e:
        print("[aes_encrypt] exception:", e)
        return None

# AES-GCM解密，nonce + ciphertext + tag分离，先校验tag失败抛异常
def aes_decrypt(key, data):
    if len(data) < 12 + 16:
        raise ValueError("数据长度太短，无法包含nonce和tag")
    nonce = data[:12]
    tag = data[-16:]
    ciphertext = data[12:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # 先校验 tag = decrypt_and_verify
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# -------------------------------------------------------------------------
# 使用 x25519 交换共享秘钥，后使用KDF获得32字节密钥
# -------------------------------------------------------------------------
def derive_key(shared_secret):
    # 简单用 SHA256 哈希模拟 KDF
    import hashlib
    return hashlib.sha256(shared_secret).digest()

# 发起方，先发送公钥，再接收对方公钥，得shared_key
def key_exchange_initiator(sock):
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding =  serialization.Encoding.Raw,
        format =  serialization.PublicFormat.Raw
    )
    send_msg(sock, pub_bytes)
    peer_pub_bytes = recv_msg(sock)
    if peer_pub_bytes is None:
        raise ValueError("未收到对方公钥")
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return derive_key(shared_secret)

# 响应方，先接收公钥，再发送公钥，得shared_key
def key_exchange_responder(sock):
    peer_pub_bytes = recv_msg(sock)
    if peer_pub_bytes is None:
        raise ValueError("未收到对方公钥")
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding =  serialization.Encoding.Raw,
        format =  serialization.PublicFormat.Raw
    )
    send_msg(sock, pub_bytes)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    return derive_key(shared_secret)

# -------------------------------------------------------------------------
# 发送线程功能，输入明文，发加密后的消息, 用异常捕获防止崩溃
# -------------------------------------------------------------------------
def send_loop(sock, key):
    print("[send_loop] 输入文本，输入 exit 退出发送。")
    while True:
        try:
            text = input()
            if text.lower() == "exit":
                print("[send_loop] 退出发送线程。")
                break
            plaintext = text.encode('utf-8')
            encrypted = aes_encrypt(key, plaintext)
            if encrypted is None:
                print("[send_loop] 加密失败，消息不发送。")
                continue
            send_msg(sock, encrypted)
        except Exception as e:
            print("[send_loop] 异常:", e)
            break
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    sock.close()

# -------------------------------------------------------------------------
# 接收线程功能，解密数据先校验TAG，失败报告错误，不崩溃
# -------------------------------------------------------------------------
def recv_loop(sock, key):
    print("[recv_loop] 启动接收。")
    while True:
        try:
            data = recv_msg(sock)
            if data is None:
                print("[recv_loop] 连接关闭或未收到消息，退出接收。")
                break
            try:
                plaintext = aes_decrypt(key, data)
            except Exception as de:
                print("[recv_loop] 解密失败或 tag 不匹配:", str(de))
                continue
            print("[recv_loop] 收到消息:", plaintext.decode('utf-8', errors='replace'))
        except Exception as e:
            print("[recv_loop] 异常:", e)
            break
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    sock.close()

# -------------------------------------------------------------------------
# 服务器逻辑，绑定端口，等待连接，完成密钥交换，启动收发线程
# -------------------------------------------------------------------------
def run_server(bind_ip, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_ip, bind_port))
    s.listen(1)
    print("[server] 监听 %s:%d" % (bind_ip, bind_port))
    conn, addr = s.accept()
    print("[server] 接收到连接：", addr)
    try:
        key = key_exchange_responder(conn)
    except Exception as e:
        print("[server] 密钥交换失败:", e)
        conn.close()
        s.close()
        return
    print("[server] 密钥交换成功，开始收发")

    recv_t = threading.Thread(target=recv_loop, args=(conn, key))
    send_t = threading.Thread(target=send_loop, args=(conn, key))
    recv_t.start()
    send_t.start()

    send_t.join()
    recv_t.join()
    s.close()
    print("[server] 退出")

# -------------------------------------------------------------------------
# 客户端逻辑，连接服务器，完成密钥交换，启动收发线程
# -------------------------------------------------------------------------
def run_client(server_ip, server_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[client] 连接 %s:%d" % (server_ip, server_port))
    try:
        s.connect((server_ip, server_port))
    except Exception as e:
        print("[client] 连接失败:", e)
        return
    print("[client] 连接成功")

    try:
        key = key_exchange_initiator(s)
    except Exception as e:
        print("[client] 密钥交换失败:", e)
        s.close()
        return
    print("[client] 密钥交换完成，开始收发")

    recv_t = threading.Thread(target=recv_loop, args=(s, key))
    send_t = threading.Thread(target=send_loop, args=(s, key))
    recv_t.start()
    send_t.start()

    send_t.join()
    recv_t.join()
    s.close()
    print("[client] 退出")

def usage():
    print("用法:")
    print("  作为服务器: %s server bind_ip bind_port" % sys.argv[0])
    print("  作为客户端: %s client server_ip server_port" % sys.argv[0])

if __name__ == "__main__":
    if len(sys.argv) < 4:
        usage()
        sys.exit(1)

    mode = sys.argv[1].lower()
    if mode == "server":
        bind_ip = sys.argv[2]
        try:
            bind_port = int(sys.argv[3])
        except ValueError:
            print("端口必须是整数")
            sys.exit(1)
        run_server(bind_ip, bind_port)
    elif mode == "client":
        server_ip = sys.argv[2]
        try:
            server_port = int(sys.argv[3])
        except ValueError:
            print("端口必须是整数")
            sys.exit(1)
        run_client(server_ip, server_port)
    else:
        usage()
        sys.exit(1)
