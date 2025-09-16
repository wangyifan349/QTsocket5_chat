#!/usr/bin/env python3
"""
secure_chat_no_class_improved.py
点对点交互式聊天（单文件、无 class、无列表推导）。
- 握手：临时 X25519 密钥对（ephemeral）互换公钥 -> 通过 X25519 计算共享秘密
- 派生：HKDF-SHA256(salt=None, info=...) -> 32 字节会话密钥（用于 AES-256-GCM）
- 加密：AES-256-GCM（cryptography.hazmat.primitives.ciphers.aead.AESGCM）
  - nonce: 随机 12 字节（NONCE_LEN）
  - AAD: UTC ISO8601 时间戳（UTF-8），放入帧并作为认证数据
  - 密文包含 GCM 的 tag（AESGCM 加密输出包含 tag）
- 网络帧：4 字节大端长度前缀 || payload
  payload = key_id(4) || nonce(12) || aad_len(2) || aad || ciphertext
- 重放防护：内存循环队列 (deque) + set，键为 (nonce, aad, len(ciphertext))
- 线程模型：独立发送线程（读取 stdin -> 加密 -> 发送）和接收线程（读取 socket -> 解析 -> 解密 -> 显示）
- 设计原则：保持简单、可读、避免在多个线程同时写 socket 导致的帧粘连（使用 send_lock）
"""
import socket
import threading
import struct
import os
import sys
from collections import deque
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ---------------------------------------------------------------------
# 协议/实现常量（精确含义）
# ---------------------------------------------------------------------
KEY_ID_LEN = 4                # 会话标识长度：从派生的对称密钥取前 N 字节作为本地会话 id（用于快速检测不同会话）
NONCE_LEN = 12                # AES-GCM 推荐 12 字节 nonce；必须保证在同一密钥下不重复
AAD_LEN_FIELD = 2             # 用于编码 AAD 长度的字段字节数（unsigned big-endian）
MAX_AAD = 65535               # 与 AAD_LEN_FIELD 对应的上限（2 字节能表示的最大值）
REPLAY_CACHE_SIZE = 256       # 内存中重放缓存的最大条目数（循环缓存实现）
MAX_CLOCK_SKEW_SECONDS = 300  # 允许的时钟偏差（秒）；大于此视为旧消息/重放并拒绝
ENCODING = 'utf-8'            # 文本编码：发送前编码，接收后尝试以此解码
# ---------------------------------------------------------------------
# 网络读写：长度前缀帧（原子消息）
# 语义：发送端先写 4 字节大端长度，再写 payload；接收端先读 4 字节长度再读完整 payload
# 必须保证所有写操作由同一锁保护以避免多个线程写时造成帧粘连
# ---------------------------------------------------------------------
def send_with_len(sock, data, send_lock):
    """
    原子发送：写入 4 字节大端长度前缀，然后写 payload。
    - send_lock: 用于串行化对 socket 的写操作（必须由所有写路径共享）。
    - 如果 sendall 抛异常，异常向上抛出由调用者处理（通常意味着连接需要关闭）。
    """
    send_lock.acquire()
    try:
        sock.sendall(struct.pack('!I', len(data)) + data)
    finally:
        send_lock.release()
def recv_all(sock, n):
    """
    读取精确 n 字节：
    - 循环调用 recv 直到收到 n 字节或连接关闭/错误。
    - 返回 bytes 长度为 n；若连接提前关闭或发生读取错误返回 None。
    - 不应假设单次 recv 会返回所需全部数据（TCP 是流式）。
    """
    buf = b''
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf
def recv_with_len(sock):
    """
    从 socket 读取长度前缀帧：
    - 先读 4 字节大端长度；若连接关闭返回 None。
    - 再按该长度读出 payload 并返回（payload 可能为空 b''）。
    """
    raw = recv_all(sock, 4)
    if not raw:
        return None
    (n,) = struct.unpack('!I', raw)
    if n == 0:
        return b''
    return recv_all(sock, n)
# ---------------------------------------------------------------------
# 密钥派生与时间戳工具
# ---------------------------------------------------------------------
def derive_key(shared_secret, info=b'handshake secure chat', length=32):
    """
    从 X25519 共享秘密派生对称会话密钥：
    - 使用 HKDF-SHA256，salt=None（注意：在更严格的部署中应使用非空 salt）
    - info 字段用于区分协议/用途，防止跨用途密钥重用
    - 返回长度为 length 的字节串（默认 32，用于 AES-256）
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(shared_secret)
def current_timestamp_iso():
    """返回当前 UTC 时间的 ISO8601 字符串（秒精度），用作 AAD 的内容。"""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')
def parse_timestamp_iso(s):
    """
    解析 ISO8601 字符串为 datetime：
    - 直接使用 datetime.fromisoformat，调用者需处理可能的异常（不合法格式）。
    - 期望包含时区信息或明确为 UTC 格式（脚本在生成时使用 timezone.utc）。
    """
    return datetime.fromisoformat(s)
# ---------------------------------------------------------------------
# 重放缓存（deque + set，无 class）
# - 使用线程锁保护读写
# - 键采用 (nonce, aad, len(ciphertext)) 来减少不同消息产生相同 nonce+aAD 的碰撞风险
# ---------------------------------------------------------------------
def init_replay_cache(size):
    """
    初始化重放缓存结构，返回三元组 (deque, set, lock)：
    - deque: 用作固定容量的 FIFO，自动弹出最旧条目
    - set: 用于 O(1) 查重
    - lock: 线程锁，保护 deque 与 set 的一致性
    """
    dq = deque(maxlen=size)
    st = set()
    lock = threading.Lock()
    return (dq, st, lock)

def replay_seen(cache, item):
    """
    判断 item 是否在重放缓存中（线程安全）。
    - item: 应为可哈希类型（本脚本使用 bytes/tuple）
    - 返回 True 表示已见过（疑似重放）
    """
    dq, st, lock = cache
    with lock:
        return item in st
def replay_add(cache, item):
    """
    将 item 加入重放缓存（线程安全）。
    - 若已存在则返回 False（未新增）。
    - 若缓存已满会弹出最旧项并从集合中删除相应项。
    - 返回 True 表示成功新增。
    """
    dq, st, lock = cache
    with lock:
        if item in st:
            return False
        if len(dq) == dq.maxlen:
            old = dq.popleft()
            if old in st:
                st.remove(old)
        dq.append(item)
        st.add(item)
        return True
# ---------------------------------------------------------------------
# 帧构建与解析（payload 内结构）
# payload = key_id || nonce || aad_len || aad || ciphertext
# - key_id: 固定 KEY_ID_LEN 字节，来源于对称密钥的前缀
# - nonce: 随机 NONCE_LEN 字节
# - aad_len: AAD 长度（unsigned big-endian，字节数）
# - aad: 作为 AES-GCM AAD 的字节（本脚本为 UTF-8 的 ISO8601 时间戳）
# - ciphertext: AESGCM.encrypt 返回的密文（包含 tag）
# ---------------------------------------------------------------------
def build_payload(key_id, aesgcm, plaintext_bytes, timestamp_str):
    """
    构建 payload：
    - plaintext_bytes: 明文字节
    - timestamp_str: 用作 AAD 的时间戳字符串（将被 UTF-8 编码）
    - 返回完整 payload（不含 4 字节外层长度前缀）
    - 在调用前应确保 plaintext_bytes 与 timestamp_str 合法并合理长度
    """
    aad = timestamp_str.encode(ENCODING)
    if len(aad) > MAX_AAD:
        raise ValueError('AAD too large')
    nonce = os.urandom(NONCE_LEN)
    # AESGCM.encrypt 返回 ciphertext||tag（已验证 tag 长度）
    ct = aesgcm.encrypt(nonce, plaintext_bytes, aad)
    aad_len_field = struct.pack('!H', len(aad))
    return key_id + nonce + aad_len_field + aad + ct
def parse_payload(data, expected_key_id):
    """
    解析 payload 并返回 (nonce, aad, ciphertext)：
    - 验证最小长度以避免索引越界
    - 验证 key_id 匹配 expected_key_id（防止错用会话密钥导致解密失败或自回显）
    - 读取 aad_len 并确保剩余长度足够
    - 确保 ciphertext 至少包含 GCM tag（一般为 16 字节）
    - 若任何检查失败抛出 ValueError
    """
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
    if len(ct) < 16:
        # AES-GCM Tag 最少 16 字节（cryptography 默认 128-bit tag）
        raise ValueError('ciphertext too short (missing tag)')
    return nonce, aad, ct
# ---------------------------------------------------------------------
# 发送线程：从 stdin 读取文本 -> 编码 -> 加密 -> 发送
# 规则：
# - 空行忽略；输入 "/quit" 会触发本地退出逻辑
# - 使用 send_lock 串行化 socket 写入
# - 任何写错误将设置 stop_event 以通知其它线程退出
# ---------------------------------------------------------------------
def send_thread_func(sock, aesgcm, key_id, send_lock, stop_event):
    try:
        while not stop_event.is_set():
            try:
                line = input()
            except EOFError:
                break
            if line is None:
                break
            s = line.rstrip('\n')
            if s == '':
                continue
            if s == '/quit':
                stop_event.set()
                break
            try:
                pt_bytes = s.encode(ENCODING)
            except Exception as e:
                print('[send] encode failed:', e)
                continue
            ts = current_timestamp_iso()
            try:
                payload = build_payload(key_id, aesgcm, pt_bytes, ts)
            except Exception as e:
                print('[send] build payload failed:', e)
                continue
            try:
                send_with_len(sock, payload, send_lock)
            except Exception as e:
                # 发送失败通常意味着连接断开或网络错误，触发停止流程
                print('[send] socket send failed:', e)
                stop_event.set()
                break
    except Exception as e:
        # 捕获线程内部异常并尝试通知主流程停止
        print('[send thread] exception:', e)
        stop_event.set()
# ---------------------------------------------------------------------
# 接收线程：读取网络帧 -> 解析 -> 重放检测 -> 解密 -> 时间戳检查 -> 输出
# 规则与安全点：
# - 解密失败（认证失败）应被视为可疑并加入重放缓存以减少对相同失败帧的重复处理
# - 时间戳校验用于检测旧消息/重放；若超出允许偏差则拒绝并标记已见
# - 解密后尝试以 UTF-8 解码；若失败则以 hex 输出并标注为二进制
# - 接收线程不对 socket 执行写操作（避免与发送线程的写入竞争）
# ---------------------------------------------------------------------
def safe_decode_text(b):
    """
    尝试按 ENCODING 解码字节：
    - 返回 (text, True) 若解码成功
    - 返回 (hexstr, False) 若解码失败（以 hex 表示二进制数据）
    """
    try:
        return b.decode(ENCODING), True
    except Exception:
        return b.hex(), False
def recv_thread_func(sock, aesgcm, key_id, replay_cache, max_clock_skew_seconds, stop_event):
    try:
        while not stop_event.is_set():
            data = recv_with_len(sock)
            if data is None:
                # 连接关闭或读取错误：触发停止
                print('[recv] connection closed')
                stop_event.set()
                break
            if data == b'':
                # 忽略空 payload
                continue
            try:
                nonce, aad, ct = parse_payload(data, key_id)
            except Exception as e:
                # 格式错误或 key_id 不匹配等，丢弃但不关闭连接
                print('[recv] parse frame failed:', e)
                continue
            # 使用 (nonce, aad, len(ct)) 作为重放判重键（ct 包含 tag）
            replay_item = (nonce, aad, len(ct))
            if replay_seen(replay_cache, replay_item):
                print('[recv] replay detected, dropping')
                continue
            try:
                pt = aesgcm.decrypt(nonce, ct, aad)
            except Exception as e:
                # 解密/认证失败：视为异常帧，加入重放缓存以避免重复处理相同数据
                print('[recv] decrypt failed (auth/tag error?):', e)
                replay_add(replay_cache, replay_item)
                continue
            # 验证时间戳（AAD）
            try:
                ts_str = aad.decode(ENCODING)
                ts_dt = parse_timestamp_iso(ts_str)  # 可能抛异常 -> 走 except 分支
                now = datetime.now(timezone.utc)
                delta = abs((now - ts_dt).total_seconds())
                if delta > max_clock_skew_seconds:
                    # 时间戳偏差过大，拒绝该消息并标记为已见
                    print('[recv] timestamp skew too large ({:.0f}s), message rejected'.format(delta))
                    replay_add(replay_cache, replay_item)
                    continue
            except Exception as e:
                # AAD 不是合法时间戳或解码失败：标记并拒绝
                print('[recv] invalid timestamp/aad:', e)
                replay_add(replay_cache, replay_item)
                continue
            # 通过所有检查：标记已见并显示
            replay_add(replay_cache, replay_item)
            text, ok = safe_decode_text(pt)
            if ok:
                print('[peer {}] {}'.format(ts_str, text))
            else:
                print('[peer {}] (binary hex) {}'.format(ts_str, text))
    except Exception as e:
        # 捕获线程异常并通知停止
        print('[recv thread] exception:', e)
        stop_event.set()
# ---------------------------------------------------------------------
# 握手实现（客户端与服务端对应）
# - 使用 X25519 ephemeral 密钥对（临时密钥），公钥以 raw bytes 序列化（Encoding.Raw, PublicFormat.Raw）
# - 握手消息也使用长度前缀帧传输（send_with_len/recv_with_len 保证帧边界）
# - 顺序约定：
#   - 客户端：先发送 client_pub，再接收 server_pub
#   - 服务器：先接收 client_pub，再发送 server_pub
# - 握手完成后双方计算 shared_secret 并通过 HKDF 派生对称密钥
# - 返回的对称密钥应立即用于 AESGCM(sym_key)
# ---------------------------------------------------------------------
def perform_handshake_as_server(conn):
    """
    服务端握手：
    - 生成 ephemeral X25519 私钥并获取公钥 raw bytes
    - 阻塞接收客户端公钥（长度前缀帧）
    - 发送服务端公钥（长度前缀帧）
    - 使用 server_priv.exchange(client_pub) 计算共享秘密并派生会话密钥
    - 若接收失败抛出 ConnectionError
    """
    server_priv = x25519.X25519PrivateKey.generate()
    server_pub = server_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    client_pub_bytes = recv_with_len(conn)
    if client_pub_bytes is None:
        raise ConnectionError('failed to receive client public key')
    temp_lock = threading.Lock()
    send_with_len(conn, server_pub, temp_lock)
    client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared = server_priv.exchange(client_pub)
    return derive_key(shared)
def perform_handshake_as_client(conn):
    """
    客户端握手：
    - 生成 ephemeral X25519 私钥并发送公钥（raw bytes）
    - 阻塞接收服务端公钥
    - 通过 exchange 计算共享秘密并派生会话密钥
    - 若接收失败抛出 ConnectionError
    """
    client_priv = x25519.X25519PrivateKey.generate()
    client_pub = client_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    temp_lock = threading.Lock()
    send_with_len(conn, client_pub, temp_lock)
    server_pub_bytes = recv_with_len(conn)
    if server_pub_bytes is None:
        raise ConnectionError('failed to receive server public key')
    server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared = client_priv.exchange(server_pub)
    return derive_key(shared)
# ---------------------------------------------------------------------
# 主流程：server/client 交互式运行
# - 完成握手 -> 用派生密钥构造 AESGCM -> 提取 key_id -> 启动发送/接收线程
# - send_lock: 保护所有对 socket 的写操作（握手中临时发送也应被保护）
# - stop_event: 用于在线程间协作以优雅关闭
# - 线程为 daemon，以便主线程退出时可快速终止；但脚本使用 join 等候发送线程完成以实现优雅终止
# ---------------------------------------------------------------------
def run_server_interactive(bind_host, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 允许程序快速重启后快速绑定端口（仅限测试/开发环境）
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, bind_port))
    s.listen(1)
    print('Server listening on {}:{}'.format(bind_host, bind_port))
    conn, addr = s.accept()
    print('Accepted connection from', addr)
    try:
        sym = perform_handshake_as_server(conn)  # 派生的对称密钥（bytes）
        aesgcm = AESGCM(sym)                      # 用于加解密的 AESGCM 对象
        key_id = sym[:KEY_ID_LEN]                # 本地会话标识（用于快速检查）
        print('Handshake complete. key_id:', key_id.hex())
        send_lock = threading.Lock()
        replay_cache = init_replay_cache(REPLAY_CACHE_SIZE)
        stop_event = threading.Event()
        # 接收线程只读 socket（解密/显示）
        t_recv = threading.Thread(target=recv_thread_func, args=(conn, aesgcm, key_id, replay_cache, MAX_CLOCK_SKEW_SECONDS, stop_event), daemon=True)
        # 发送线程负责读取 stdin 并写 socket（写操作受 send_lock 保护）
        t_send = threading.Thread(target=send_thread_func, args=(conn, aesgcm, key_id, send_lock, stop_event), daemon=True)
        t_recv.start()
        t_send.start()
        # 等待发送线程退出（例如用户输入 /quit 或 EOF）
        t_send.join()
        # 通知接收线程停止并尝试关闭连接
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
        t_send = threading.Thread(target=send_thread_func, args=(s, aesgcm, key_id, send_lock, stop_event), daemon=True)
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
# 程序入口：支持命令行参数或交互式输入以选择 server/client 与地址
# 命令行用法示例：
#   python secure_chat_no_class_improved.py server 0.0.0.0 12345
#   python secure_chat_no_class_improved.py client 127.0.0.1 12345
# 若无参数则进入交互式询问模式（保持原始行为）
# ---------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    if len(args) >= 1:
        mode = args[0].lower()
        if mode.startswith('s'):
            is_server = True
        elif mode.startswith('c'):
            is_server = False
        else:
            print('Unknown mode argument; use "server" or "client"')
            return
        host = args[1] if len(args) >= 2 else ( '0.0.0.0' if is_server else '127.0.0.1' )
        try:
            port = int(args[2]) if len(args) >= 3 else 12345
        except Exception:
            port = 12345
    else:
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
        else:
            host = input('Peer address (default 127.0.0.1): ').strip()
            if not host:
                host = '127.0.0.1'
            port_s = input('Peer port (default 12345): ').strip()
            try:
                port = int(port_s) if port_s else 12345
            except Exception:
                port = 12345
    if is_server:
        run_server_interactive(host, port)
    else:
        run_client_interactive(host, port)
if __name__ == '__main__':
    main()
