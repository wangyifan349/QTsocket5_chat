#!/usr/bin/env python3
import socket
import threading
import time
import sys
import os
import struct
import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# =============================================
# 网络辅助函数：确保从 socket 中接收指定字节数
# =============================================
def recvn(sock, n):
    data = b""
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
        except Exception as e:
            return None
        if not packet:
            return None
        data += packet
    return data
# =============================================
# AES-GCM 加密与解密函数, 结果采用 JSON 格式传输
# =============================================
def aes_encrypt(key, plaintext):
    # 创建 AES-GCM 加密器，自动生成 nonce
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    # 构造 JSON 对象，字段均采用十六进制字符串表示
    payload = {
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    # 返回 JSON 序列化后的字节序列
    return json.dumps(payload).encode("utf-8")
def aes_decrypt(key, json_ciphertext):
    try:
        # 解析 JSON
        payload = json.loads(json_ciphertext.decode("utf-8"))
        nonce = bytes.fromhex(payload["nonce"])
        tag = bytes.fromhex(payload["tag"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
    except Exception as e:
        raise ValueError("JSON 解析或十六进制转换失败: " + str(e))
    # 创建 AES-GCM 解密器，并进行解密和 tag 校验
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        raise ValueError("解密或 tag 校验失败: " + str(e))
    return plaintext
# =============================================
# X25519 密钥协商握手过程
# =============================================
def do_x25519_handshake(sock, is_server):
    """
    按照约定协议交换公钥：
    - 公钥长度用 2 字节网络序先发送，再发送公钥原始字节
    """
    # 生成本地 X25519 密钥对
    local_private_key = X25519PrivateKey.generate()
    local_public_key = local_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    if is_server:
        # 服务器：先接收客户端公钥，再发送自己的公钥
        header = recvn(sock, 2)
        if not header:
            raise ConnectionError("读取客户端公钥长度失败")
        client_pub_len = struct.unpack("!H", header)[0]
        client_public = recvn(sock, client_pub_len)
        if not client_public:
            raise ConnectionError("接收客户端公钥失败")
        # 发送自己的公钥
        sock.sendall(struct.pack("!H", len(local_public_key)) + local_public_key)
    else:
        # 客户端：先发送自己的公钥，再接收服务器的公钥
        sock.sendall(struct.pack("!H", len(local_public_key)) + local_public_key)
        header = recvn(sock, 2)
        if not header:
            raise ConnectionError("读取服务器公钥长度失败")
        server_pub_len = struct.unpack("!H", header)[0]
        client_public = recvn(sock, server_pub_len)
        if not client_public:
            raise ConnectionError("接收服务器公钥失败")
    # 使用对方公钥计算共享密钥
    try:
        peer_public_key = X25519PublicKey.from_public_bytes(client_public)
    except Exception as e:
        raise ValueError("无效的对方公钥: " + str(e))
    shared_key = local_private_key.exchange(peer_public_key)
    print("握手成功，生成共享密钥:", shared_key.hex())
    # 实际应用中建议使用 HKDF 派生 AES 密钥，此处直接使用 shared_key（32字节）
    return shared_key
# =============================================
# 发送线程：读取终端输入，加密后通过 socket 发送
# =============================================
def sender(sock, key, stop_event):
    try:
        while not stop_event.is_set():
            try:
                message = input()
            except EOFError:
                break
            if not message:
                continue
            # 使用 AES-GCM 加密
            encrypted = aes_encrypt(key, message.encode("utf-8"))
            # 先发送4字节长度，再发送 JSON 加密数据
            try:
                sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)
            except Exception as e:
                print("发送失败:", e)
                stop_event.set()
                break
    except Exception as e:
        print("发送线程异常:", e)
        stop_event.set()
# =============================================
# 接收线程：从 socket 接收数据，解密后输出到终端
# =============================================
def receiver(sock, key, stop_event):
    try:
        while not stop_event.is_set():
            header = recvn(sock, 4)
            if not header:
                print("连接可能已断开")
                stop_event.set()
                break
            (msg_len,) = struct.unpack("!I", header)
            data = recvn(sock, msg_len)
            if not data:
                print("未接收到完整数据，连接断开")
                stop_event.set()
                break
            try:
                decrypted = aes_decrypt(key, data)
                print("对方:", decrypted.decode("utf-8"))
            except Exception as e:
                print("解密失败:", e)
    except Exception as e:
        print("接收线程异常:", e)
        stop_event.set()
# =============================================
# 客户端运行主流程（自动重连）
# =============================================
def run_client(server_ip, server_port):
    reconnect_interval = 5  # 重连间隔秒数
    while True:
        print("尝试连接到服务器 {}:{} ...".format(server_ip, server_port))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, server_port))
            print("成功连接到服务器 {}:{}".format(server_ip, server_port))
            # 执行 X25519 握手（充当客户端角色）
            key = do_x25519_handshake(sock, is_server=False)
            stop_event = threading.Event()
            t_send = threading.Thread(target=sender, args=(sock, key, stop_event))
            t_recv = threading.Thread(target=receiver, args=(sock, key, stop_event))
            t_send.start()
            t_recv.start()
            t_send.join()
            t_recv.join()
            sock.close()
            if stop_event.is_set():
                print("检测到断线，准备重连...")
        except Exception as e:
            print("连接或通信过程中发生异常:", e)
        print("将在 {} 秒后重连...".format(reconnect_interval))
        time.sleep(reconnect_interval)
# =============================================
# 服务器端运行主流程（断线后继续监听新的连接）
# =============================================
def run_server(listen_port):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("", listen_port))
    server_sock.listen(5)
    print("服务器正在监听端口 {} ...".format(listen_port))
    while True:
        try:
            conn, addr = server_sock.accept()
            print("接受到来自 {} 的连接".format(addr))
            try:
                key = do_x25519_handshake(conn, is_server=True)
            except Exception as e:
                print("握手失败:", e)
                conn.close()
                continue
            stop_event = threading.Event()
            t_send = threading.Thread(target=sender, args=(conn, key, stop_event))
            t_recv = threading.Thread(target=receiver, args=(conn, key, stop_event))
            t_send.start()
            t_recv.start()
            t_send.join()
            t_recv.join()
            print("与 {} 的连接已断开".format(addr))
            conn.close()
        except Exception as e:
            print("服务器运行过程中异常:", e)
    server_sock.close()
# =============================================
# 主函数: 根据用户的选择以客户端或服务器模式运行
# =============================================
def main():
    mode = ""
    while mode not in ["s", "c"]:
        mode = input("请输入运行模式 [s=服务器, c=客户端]: ").strip().lower()
    port = 5000  # 默认通信端口
    try:
        if mode == "s":
            run_server(port)
        else:
            server_ip = input("请输入服务器IP地址: ").strip()
            run_client(server_ip, port)
    except KeyboardInterrupt:
        print("\n检测到 Ctrl+C，程序退出")
        sys.exit(0)
if __name__ == "__main__":
    main()
