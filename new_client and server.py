"""
python3 app.py server
# 或
python3 app.py client
"""

#!/usr/bin/env python3
import socket
import threading
import struct
import os
import json
import time
import sys
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError

# --------- 日志功能 ---------
logfile = "app.log"
log_lock = threading.Lock()

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    with log_lock:
        print(line)
        try:
            with open(logfile, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

# --------- HKDF 函数 ---------
def hkdf_derive(key_material, salt=b"handshake salt", info=b"AES key"):
    h = HMAC.new(salt, digestmod=SHA256)
    h.update(key_material)
    prk = h.digest()  # pseudorandom key

    h2 = HMAC.new(prk, digestmod=SHA256)
    h2.update(info + b"\x01")
    return h2.digest()  # 32 字节密钥

# --------- 包数据发送 ---------
def send_packet(conn, data):
    encoded = data.encode()
    packet_length = struct.pack(">I", len(encoded))
    conn.sendall(packet_length + encoded)

# --------- 接收完整数据 ---------
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

# --------- 接收包 ---------
def recv_packet(conn):
    header = recv_all(conn, 4)
    if not header:
        return None
    length = struct.unpack(">I", header)[0]
    data = recv_all(conn, length)
    if data is None:
        return None
    return data.decode()

# --------- 全局密钥 ---------
aes_key = None

# --------- 握手过程 ---------
def handshake(conn, is_server):
    global aes_key

    try:
        my_private = PrivateKey.generate()
        my_public = my_private.public_key

        if is_server:
            # 服务器先接收客户端公钥，再发自己公钥
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("Did not receive client's public key")
            peer_pub = json.loads(peer_pub_json).get("pub")
            if peer_pub is None:
                raise RuntimeError("Client public key missing")
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
        else:
            # 客户端先发公钥，再接服务器公钥
            send_packet(conn, json.dumps({"pub": my_public.encode().hex()}))
            peer_pub_json = recv_packet(conn)
            if peer_pub_json is None:
                raise RuntimeError("Did not receive server's public key")
            peer_pub = json.loads(peer_pub_json).get("pub")
            if peer_pub is None:
                raise RuntimeError("Server public key missing")

        peer_public = PublicKey(bytes.fromhex(peer_pub))
        shared = my_private.exchange(peer_public)
        aes_key = hkdf_derive(shared)

        log("[Handshake Success] Shared AES key: " + aes_key.hex())
        return True
    except Exception as e:
        log("[Handshake Exception] " + str(e))
        return False

# --------- 消息加密 ---------
def encrypt_message(plaintext):
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = {
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }
    return json.dumps(payload)

# --------- 消息解密 ---------
def decrypt_message(json_data):
    try:
        data = json.loads(json_data)
        nonce = bytes.fromhex(data["nonce"])
        tag = bytes.fromhex(data["tag"])
        ciphertext = bytes.fromhex(data["ciphertext"])
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError, CryptoError) as e:
        raise ValueError("Decryption or data format error: " + str(e))

# --------- 发送线程 ---------
def send_thread(conn):
    while True:
        try:
            msg = input()
            if not msg:
                continue
            encrypted = encrypt_message(msg.encode())
            send_packet(conn, encrypted)
        except Exception as e:
            log("[Send Exception] " + str(e))
            break

# --------- 接收线程 ---------
def recv_thread(conn):
    while True:
        try:
            data_json = recv_packet(conn)
            if data_json is None:
                log("[Connection Closed] Peer disconnected")
                break
            plaintext = decrypt_message(data_json)
            log("[Received] " + plaintext.decode())
        except (ValueError, CryptoError) as e:
            log("[Decryption Error] " + str(e))
        except Exception as e:
            log("[Receive Exception] " + str(e))
            break

# --------- 服务器主循环 ---------
def server_main(host="0.0.0.0", port=9999):
    global aes_key

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)

    log(f"[Server Started] Listening on {host}:{port}")

    while True:
        try:
            conn, addr = server_sock.accept()
            log(f"[Connection Established] From: {addr}")
            success = handshake(conn, is_server=True)
            if not success:
                conn.close()
                continue

            t_send = threading.Thread(target=send_thread, args=(conn,))
            t_recv = threading.Thread(target=recv_thread, args=(conn,))

            t_send.start()
            t_recv.start()

            t_send.join()
            t_recv.join()

            conn.close()
            log("[Session Ended] Connection closed, waiting for reconnection...")
        except Exception as e:
            log("[Server Exception] " + str(e))
        time.sleep(2)

# --------- 客户端主循环 ---------
def client_main(host="127.0.0.1", port=9999):
    global aes_key

    while True:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            log(f"[Connecting] Connecting to {host}:{port} ...")
            conn.connect((host, port))
            log("[Connected] Connection established")

            success = handshake(conn, is_server=False)
            if not success:
                conn.close()
                time.sleep(2)
                continue

            t_send = threading.Thread(target=send_thread, args=(conn,))
            t_recv = threading.Thread(target=recv_thread, args=(conn,))

            t_send.start()
            t_recv.start()

            t_send.join()
            t_recv.join()

            conn.close()
            log("[Session Ended] Connection closed, reconnecting...")
        except Exception as e:
            log("[Client Exception] " + str(e))
        time.sleep(2)

# --------- 主程序入口 ---------
def main():
    mode = None

    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg == "server" or arg == "s":
            mode = "server"
        elif arg == "client" or arg == "c":
            mode = "client"

    while mode is None:
        choice = input("Choose mode: (s)erver or (c)lient? ").strip().lower()
        if choice in ("s", "server"):
            mode = "server"
        elif choice in ("c", "client"):
            mode = "client"

    if mode == "server":
        port_str = input("Enter listen port [default 9999]: ").strip()
        if port_str.isdigit():
            port = int(port_str)
        else:
            port = 9999
        server_main(port=port)
    else:
        host = input("Enter server IP [default 127.0.0.1]: ").strip()
        if not host:
            host = "127.0.0.1"
        port_str = input("Enter server port [default 9999]: ").strip()
        if port_str.isdigit():
            port = int(port_str)
        else:
            port = 9999
        client_main(host=host, port=port)

if __name__ == "__main__":
    main()
