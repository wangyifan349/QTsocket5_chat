import asyncio
import os
import struct
import time
import contextlib
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# --- 常量 ---
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888
LONGTERM_KEY_FILE_SERVER = "server_longterm_key.pem"
LONGTERM_KEY_FILE_CLIENT = "client_longterm_key.pem"
SERVER_LOG_FILE = "server_messages.log"
CLIENT_LOG_FILE = "client_messages.log"
# --- 工具函数 ---
def current_time_str() -> str:
    """返回当前时间的字符串表示，方便日志输出"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
async def send_msg(writer: asyncio.StreamWriter, data: bytes):
    """
    发送消息，消息格式是4字节大端消息长度 + 消息正文
    """
    length_prefix = struct.pack(">I", len(data))
    writer.write(length_prefix)
    writer.write(data)
    await writer.drain()
async def recv_msg(reader: asyncio.StreamReader) -> bytes:
    """
    接收一条消息，先收到4字节长度，然后读取对应长度数据。
    发生读取错误抛异常。
    """
    raw_len = await reader.readexactly(4)
    length = struct.unpack(">I", raw_len)[0]
    data = await reader.readexactly(length)
    return data
def derive_shared_key(private_key: x25519.X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """
    利用本地私钥和对端公钥计算共享密钥，使用 HKDF-SHA256 做密钥派生
    """
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ephemeral-static handshake"
    ).derive(shared_secret)
    return derived_key
def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    使用 AES-GCM 加密，随机产生12字节nonce，返回 nonce + ciphertext
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext
def decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-GCM 解密，前12字节是nonce，后面是密文
    """
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
def write_log(filename: str, prefix: str, plaintext: bytes, ciphertext: bytes):
    """
    把明文和密文写入日志文件，带时间戳
    prefix用来标识发送或接收，方便区分
    """
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"[{current_time_str()}] {prefix} Plaintext: {plaintext.decode(errors='replace')}\n")
        f.write(f"[{current_time_str()}] {prefix} Ciphertext(hex): {ciphertext.hex()}\n\n")
def save_longterm_key(filename: str, private_key: x25519.X25519PrivateKey):
    """
    把长期私钥以纯Raw格式保存到文件（仅供示范，不加密）
    """
    data = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as f:
        f.write(data)
def load_longterm_key(filename: str) -> Optional[x25519.X25519PrivateKey]:
    """
    从文件加载长期私钥，如果文件不存在返回None
    """
    if not os.path.exists(filename):
        return None
    data = open(filename, "rb").read()
    return x25519.X25519PrivateKey.from_private_bytes(data)
# --- 服务端实现 ---
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    处理一个客户端连接，功能：
      - 交换长期公钥
      - 循环收发消息
      - 每条消息带客户端ephemeral公钥，用长期密钥推导会话密钥解密消息
      - 回复消息使用服务器生成的ephemeral密钥和客户端长期公钥推导密钥加密
      - 记录日志
      - 任何异常或断开则关闭连接
    """
    peer = writer.get_extra_info("peername")
    print(f"[Server] Client connected: {peer}")
    # 加载服务器长期密钥或新生成保存
    srv_priv = load_longterm_key(LONGTERM_KEY_FILE_SERVER)
    if srv_priv is None:
        srv_priv = x25519.X25519PrivateKey.generate()
        save_longterm_key(LONGTERM_KEY_FILE_SERVER, srv_priv)
    srv_pub_bytes = srv_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    try:
        # 先接收客户端长期公钥
        client_longterm_pub_bytes = await recv_msg(reader)
        # 发送服务器长期公钥给客户端
        await send_msg(writer, srv_pub_bytes)
        print(f"[Server] Long-term keys exchanged with {peer}")
        while True:
            # 接收消息，格式：32字节 ephemeral 公钥 + AES-GCM 密文
            data = await recv_msg(reader)
            if len(data) < 44:
                # 32字节ephemeral pub + 12字节nonce至少44字节
                print(f"[Server] Message too short from {peer}, closing")
                break
            ephemeral_pub_bytes = data[:32]
            encrypted = data[32:]
            # 用服务器长期私钥与客户端发送的ephemeral公钥推导会话密钥解密
            try:
                session_key = derive_shared_key(srv_priv, ephemeral_pub_bytes)
                plaintext = decrypt(session_key, encrypted)
            except Exception as e:
                print(f"[Server] Decrypt failed from {peer}: {e}")
                break
            print(f"[Server] From {peer}: {plaintext.decode(errors='replace')}")
            write_log(SERVER_LOG_FILE, "Received", plaintext, encrypted)
            # 回复消息，服务器生成ephemeral密钥
            srv_ephemeral_priv = x25519.X25519PrivateKey.generate()
            srv_ephemeral_pub = srv_ephemeral_priv.public_key()
            # 用服务器ephemeral私钥和客户端长期公钥推导回复会话密钥
            reply_key = derive_shared_key(srv_ephemeral_priv, client_longterm_pub_bytes)
            reply_plain = f"Server ack: {plaintext.decode(errors='replace')}".encode()
            encrypted_reply = encrypt(reply_key, reply_plain)
            write_log(SERVER_LOG_FILE, "Sent", reply_plain, encrypted_reply)
            # 返回消息组成：32字节ephemeral公钥 + 密文
            reply_msg = srv_ephemeral_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) + encrypted_reply
            await send_msg(writer, reply_msg)
    except (asyncio.IncompleteReadError, ConnectionResetError):
        # 客户端断开连接
        print(f"[Server] Client {peer} disconnected")
    except Exception as e:
        print(f"[Server] Exception handling {peer}: {e}")
    writer.close()
    await writer.wait_closed()
    print(f"[Server] Connection with {peer} closed.")
async def start_server():
    """
    启动TCP服务器，监听客户端连接，调用handle_client处理
    """
    server = await asyncio.start_server(handle_client, SERVER_HOST, SERVER_PORT)
    addr = server.sockets[0].getsockname()
    print(f"[Server] Serving on {addr}")
    async with server:
        await server.serve_forever()
# --- 客户端实现 ---
async def client_read_messages(reader: asyncio.StreamReader,
                               client_priv: x25519.X25519PrivateKey,
                               log_file: str):
    """
    在连接后循环读取服务器回复消息，格式：
      32字节服务器ephemeral公钥 + AES-GCM密文
    使用客户端长期私钥和服务器ephemeral公钥派生密钥解密
    出现连接断开异常则退出
    """
    while True:
        data = await recv_msg(reader)
        if len(data) < 44:
            print("[Client] Server reply message too short")
            continue
        server_ephemeral_pub_bytes = data[:32]
        encrypted = data[32:]
        session_key = derive_shared_key(client_priv, server_ephemeral_pub_bytes)
        plaintext = decrypt(session_key, encrypted)
        print(f"[Client] Server reply: {plaintext.decode(errors='replace')}")
        write_log(log_file, "Received", plaintext, encrypted)
async def client_send_messages(writer: asyncio.StreamWriter,
                               server_longterm_pub_bytes: bytes,
                               client_priv: x25519.X25519PrivateKey,
                               log_file: str):
    """
    循环定时发送消息到服务器，逻辑：
      每条消息包含一个新生成ephemeral密钥对
      使用该ephemeral私钥和对方长期公钥派生密钥加密消息
      发送内容：32字节ephemeral公钥 + AES-GCM密文
    """
    i = 0
    while True:
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        session_key = derive_shared_key(ephemeral_priv, server_longterm_pub_bytes)
        plaintext = f"Hello server, message {i}".encode()
        encrypted = encrypt(session_key, plaintext)
        write_log(log_file, "Sent", plaintext, encrypted)
        msg = ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ) + encrypted
        await send_msg(writer, msg)
        print(f"[Client] Sent message {i}")
        i += 1
        await asyncio.sleep(2)  # 每2秒发一条消息
async def client_loop():
    """
    客户端主循环：
      - 建立连接
      - 发送客户端长期公钥，接收服务器长期公钥
      - 启动消息收发两个并发任务
      - 任一断开则关闭，等待重连3秒后再次尝试
    """
    # 载入或生成客户端长期密钥
    client_priv = load_longterm_key(LONGTERM_KEY_FILE_CLIENT)
    if client_priv is None:
        client_priv = x25519.X25519PrivateKey.generate()
        save_longterm_key(LONGTERM_KEY_FILE_CLIENT, client_priv)
    client_pub_bytes = client_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    while True:
        try:
            print("[Client] Connecting to server...")
            reader, writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
            # 发送客户端长期公钥
            await send_msg(writer, client_pub_bytes)
            # 接收服务器长期公钥
            server_longterm_pub_bytes = await recv_msg(reader)
            print("[Client] Long-term keys exchanged with server")
            # 启动收消息和发消息任务
            read_task = asyncio.create_task(client_read_messages(reader, client_priv, CLIENT_LOG_FILE))
            send_task = asyncio.create_task(client_send_messages(writer, server_longterm_pub_bytes, client_priv, CLIENT_LOG_FILE))
            # 等待任一任务完成（或异常）后取消另一任务，关闭连接，进入重连等待
            done, pending = await asyncio.wait(
                [read_task, send_task], return_when=asyncio.FIRST_EXCEPTION
            )
            for task in pending:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            writer.close()
            await writer.wait_closed()
            print("[Client] Connection closed, will reconnect in 3 seconds...")
            await asyncio.sleep(3)
        except Exception as e:
            print(f"[Client] Connection error: {e}. Retrying in 3 seconds...")
            await asyncio.sleep(3)
# --- 程序入口 ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python script.py [server|client]")
        sys.exit(1)
    role = sys.argv[1].lower()
    if role == "server":
        # 启动服务端
        asyncio.run(start_server())
    elif role == "client":
        # 启动客户端
        asyncio.run(client_loop())
    else:
        print("Invalid role. Use 'server' or 'client'.")
        sys.exit(1)
