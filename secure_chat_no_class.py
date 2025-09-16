#!/usr/bin/env python3
"""
secure_chat_no_class.py
交互式单文件程序（无 class、无列表推导），X25519 握手 -> HKDF -> AES-256-GCM。
消息包含时间戳作为 AAD，nonce 随机12字节。发送/接收在独立线程运行。
"""
import socket
import threading
import struct
import os
from collections import deque
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ---------------------------------------------------------------------
# 配置常量
# ---------------------------------------------------------------------
KEY_ID_LEN = 4                # 对称 key_id 长度（用于区分并避免回显）
NONCE_LEN = 12                # AES-GCM 推荐 12 字节 nonce
AAD_LEN_FIELD = 2             # AAD 长度字段（2 字节，支持到 65535）
MAX_AAD = 65535
REPLAY_CACHE_SIZE = 256       # 简单重放缓存大小（循环队列 + 集合）
MAX_CLOCK_SKEW_SECONDS = 300  # 允许的最大时钟偏差（秒）
# ---------------------------------------------------------------------
# 辅助：网络读写（长度前缀帧）
# ---------------------------------------------------------------------
def send_with_len(sock, data, send_lock):
    """在发送时用 send_lock 保护写入，避免两个线程同时写入导致的数据混淆。"""
    send_lock.acquire()
    try:
        # 4 字节大端长度前缀
        sock.sendall(struct.pack('!I', len(data)) + data)
    finally:
        send_lock.release()
def recv_all(sock, n):
    """从 socket 精确读取 n 字节；返回 None 表示连接已关闭/错误。"""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
def recv_with_len(sock):
    """读取长度前缀帧并返回 payload（或 None 表示连接已关闭）。"""
    raw = recv_all(sock, 4)
    if not raw:
        return None
    (n,) = struct.unpack('!I', raw)
    if n == 0:
        return b''
    return recv_all(sock, n)
# ---------------------------------------------------------------------
# 密钥派生与时间戳
# ---------------------------------------------------------------------
def derive_key(shared_secret, info=b'handshake secure chat', length=32):
    """HKDF-SHA256 从共享密钥派生对称密钥（32 bytes -> AES-256-GCM）。"""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared_secret)
def current_timestamp_iso():
    """返回 UTC ISO8601 字符串（到秒）。"""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')
def parse_timestamp_iso(s):
    """解析 ISO8601 时间字符串为 datetime（可能抛异常由调用者处理）。"""
    return datetime.fromisoformat(s)
# ---------------------------------------------------------------------
# 简单重放缓存（不使用 class）
# 内部用 deque + set，提供 init_replay_cache, replay_seen, replay_add, replay_clear
# ---------------------------------------------------------------------
def init_replay_cache(size):
    dq = deque(maxlen=size)
    st = set()
    lock = threading.Lock()
    return (dq, st, lock)
def replay_seen(cache, item):
    dq, st, lock = cache
    lock.acquire()
    try:
        return item in st
    finally:
        lock.release()
def replay_add(cache, item):
    dq, st, lock = cache
    lock.acquire()
    try:
        if item in st:
            return False
        if len(dq) == dq.maxlen:
            old = dq.popleft()
            # 避免 KeyError：旧项一定在集合中
            if old in st:
                st.remove(old)
        dq.append(item)
        st.add(item)
        return True
    finally:
        lock.release()
# ---------------------------------------------------------------------
# 构建与解析消息帧
# 帧结构： key_id(4) || nonce(12) || aad_len(2) || aad || ciphertext
# AAD 为 UTF-8 编码的时间戳（ISO8601）
# ---------------------------------------------------------------------
def build_payload(key_id, aesgcm, plaintext_bytes, timestamp_str):
    aad = timestamp_str.encode('utf-8')
    if len(aad) > MAX_AAD:
        raise ValueError('AAD too large')
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext_bytes, aad)
    aad_len_field = struct.pack('!H', len(aad))
    return key_id + nonce + aad_len_field + aad + ct
def parse_payload(data, expected_key_id):
    min_len = KEY_ID_LEN + NONCE_LEN + AAD_LEN_FIELD
    if len(data) < min_len:
        raise ValueError('frame too short')
    idx = 0
    kid = data[idx:idx+KEY_ID_LEN]; idx += KEY_ID_LEN
    if kid != expected_key_id:
        raise ValueError('unexpected key id')
    nonce = data[idx:idx+NONCE_LEN]; idx += NONCE_LEN
    aad_len = struct.unpack('!H', data[idx:idx+AAD_LEN_FIELD])[0]; idx += AAD_LEN_FIELD
    if aad_len > MAX_AAD:
        raise ValueError('invalid aad length')
    if len(data) < idx + aad_len:
        raise ValueError('frame truncated for aad')
    aad = data[idx:idx+aad_len]; idx += aad_len
    ct = data[idx:]
    return nonce, aad, ct
# ---------------------------------------------------------------------
# 发送线程函数（独立线程）
# 只做读取 stdin -> 加密 -> 通过 send_with_len 发送（写用 send_lock 保护）
# ---------------------------------------------------------------------
def send_thread_func(sock, aesgcm, key_id, send_lock):
    try:
        while True:
            try:
                line = input()   # 阻塞读取用户输入
            except EOFError:
                break
            if not line:
                continue
            ts = current_timestamp_iso()
            try:
                payload = build_payload(key_id, aesgcm, line.encode('utf-8'), ts)
            except Exception as e:
                print('[send] build payload failed:', e)
                continue
            try:
                send_with_len(sock, payload, send_lock)
            except Exception as e:
                print('[send] socket send failed:', e)
                break
    except Exception as e:
        print('[send thread] exception:', e)
# ---------------------------------------------------------------------
# 接收线程函数（独立线程）
# 只读 socket -> 解析帧 -> 验证重放 -> 解密 -> 显示
# 接收线程不写 socket（避免相互干扰）
# ---------------------------------------------------------------------
def recv_thread_func(sock, aesgcm, key_id, replay_cache, max_clock_skew_seconds, stop_event):
    try:
        while not stop_event.is_set():
            data = recv_with_len(sock)
            if data is None:
                print('[recv] connection closed')
                break
            try:
                nonce, aad, ct = parse_payload(data, key_id)
            except Exception as e:
                print('[recv] parse frame failed:', e)
                continue
            # 重放检测项：使用 nonce + aad（bytes）
            replay_item = (nonce, aad)
            if replay_seen(replay_cache, replay_item):
                print('[recv] replay detected, dropping')
                continue
            # 解密
            try:
                pt = aesgcm.decrypt(nonce, ct, aad)
            except Exception as e:
                print('[recv] decrypt failed:', e)
                # 仍加入重放缓存以防止重复尝试利用重放
                replay_add(replay_cache, replay_item)
                continue
            # 验证时间戳（AAD）
            try:
                ts_str = aad.decode('utf-8')
                ts_dt = parse_timestamp_iso(ts_str)
                now = datetime.now(timezone.utc)
                delta = abs((now - ts_dt).total_seconds())
                if delta > max_clock_skew_seconds:
                    print('[recv] timestamp skew too large ({:.0f}s), message rejected'.format(delta))
                    replay_add(replay_cache, replay_item)
                    continue
            except Exception as e:
                print('[recv] invalid timestamp/aad:', e)
                replay_add(replay_cache, replay_item)
                continue
            # 标记已见，显示消息
            replay_add(replay_cache, replay_item)
            try:
                print('[peer {}] {}'.format(ts_str, pt.decode('utf-8')))
            except Exception:
                print('[peer {}] (binary)'.format(ts_str))
    except Exception as e:
        print('[recv thread] exception:', e)
# ---------------------------------------------------------------------
# 握手：Server 与 Client 对应实现
# 约定：Server 先接收客户端公钥，再发送自己的公钥（和前面对齐）
# Client 先发送公钥，再接收服务器公钥
# 使用临时锁发送握手消息以避免竞争
# ---------------------------------------------------------------------
def perform_handshake_as_server(conn):
    server_priv = x25519.X25519PrivateKey.generate()
    server_pub = server_priv.public_key().public_bytes()
    client_pub_bytes = recv_with_len(conn)
    if client_pub_bytes is None:
        raise ConnectionError('failed to receive client public key')
    temp_lock = threading.Lock()
    send_with_len(conn, server_pub, temp_lock)
    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared = server_priv.exchange(client_pub)
    return derive_key(shared)
def perform_handshake_as_client(conn):
    client_priv = x25519.X25519PrivateKey.generate()
    client_pub = client_priv.public_key().public_bytes()
    temp_lock = threading.Lock()
    send_with_len(conn, client_pub, temp_lock)
    server_pub_bytes = recv_with_len(conn)
    if server_pub_bytes is None:
        raise ConnectionError('failed to receive server public key')
    server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = client_priv.exchange(server_pub)
    return derive_key(shared)
# ---------------------------------------------------------------------
# 交互式 server 与 client 运行逻辑（主流程）
# ---------------------------------------------------------------------
def run_server_interactive(bind_host, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 允许快速重启
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, bind_port))
    s.listen(1)
    print('Server listening on {}:{}'.format(bind_host, bind_port))
    conn, addr = s.accept()
    print('Accepted connection from', addr)
    # 使用 with 以确保关闭
    try:
        sym = perform_handshake_as_server(conn)
        aesgcm = AESGCM(sym)
        key_id = sym[:KEY_ID_LEN]
        print('Handshake complete. key_id:', key_id.hex())
        # 初始化资源：发送锁、重放缓存、停止事件
        send_lock = threading.Lock()
        replay_cache = init_replay_cache(REPLAY_CACHE_SIZE)
        stop_event = threading.Event()
        # 启动接收线程（不写 socket）
        t_recv = threading.Thread(target=recv_thread_func, args=(conn, aesgcm, key_id, replay_cache, MAX_CLOCK_SKEW_SECONDS, stop_event), daemon=True)
        # 启动发送线程（写 socket，受 send_lock 保护）
        t_send = threading.Thread(target=send_thread_func, args=(conn, aesgcm, key_id, send_lock), daemon=True)
        t_recv.start()
        t_send.start()
        # 等待发送线程结束（用户输入结束）
        t_send.join()
        # 通知接收线程停止并尝试优雅关闭连接
        stop_event.set()
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()
    finally:
        s.close()
def run_client_interactive(peer_host, peer_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((peer_host, peer_port))
    try:
        sym = perform_handshake_as_client(s)
        aesgcm = AESGCM(sym)
        key_id = sym[:KEY_ID_LEN]
        print('Handshake complete. key_id:', key_id.hex())
        send_lock = threading.Lock()
        replay_cache = init_replay_cache(REPLAY_CACHE_SIZE)
        stop_event = threading.Event()
        t_recv = threading.Thread(target=recv_thread_func, args=(s, aesgcm, key_id, replay_cache, MAX_CLOCK_SKEW_SECONDS, stop_event), daemon=True)
        t_send = threading.Thread(target=send_thread_func, args=(s, aesgcm, key_id, send_lock), daemon=True)
        t_recv.start()
        t_send.start()
        t_send.join()
        stop_event.set()
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        s.close()
    finally:
        pass
# ---------------------------------------------------------------------
# 主交互入口（询问模式与地址）
# ---------------------------------------------------------------------
def main():
    print('Secure chat (interactive, no class).')
    while True:
        mode = input('Run as server or client? [s/c]: ').strip().lower()
        if mode in ('s', 'server'):
            is_server = True
            break
        if mode in ('c', 'client'):
            is_server = False
            break
    if is_server:
        host = input('Bind address (default 0.0.0.0): ').strip()
        if not host:
            host = '0.0.0.0'
        port_s = input('Bind port (default 12345): ').strip()
        try:
            port = int(port_s) if port_s else 12345
        except Exception:
            port = 12345
        run_server_interactive(host, port)
    else:
        peer = input('Peer address (default 127.0.0.1): ').strip()
        if not peer:
            peer = '127.0.0.1'
        port_s = input('Peer port (default 12345): ').strip()
        try:
            port = int(port_s) if port_s else 12345
        except Exception:
            port = 12345
        run_client_interactive(peer, port)
if __name__ == '__main__':
    main()
