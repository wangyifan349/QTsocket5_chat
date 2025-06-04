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





"""
The code below uses a Tkinter wrapper for the interface.

The code above does not have a user interface.
"""




#!/usr/bin/env python3
import socket
import threading
import time
import sys
import struct
import json
import queue
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Helper function to reliably receive n bytes from a socket
def recvn(sock, n):
    data = b""
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data += packet
    return data

# Encrypt plaintext using AES-GCM and return JSON payload (nonce, tag, ciphertext)
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    payload = {"nonce": nonce.hex(), "tag": tag.hex(), "ciphertext": ciphertext.hex()}
    return json.dumps(payload).encode("utf-8")

# Decrypt AES-GCM encrypted JSON payload and return plaintext
def aes_decrypt(key, json_ciphertext):
    payload = json.loads(json_ciphertext.decode("utf-8"))
    nonce = bytes.fromhex(payload["nonce"])
    tag = bytes.fromhex(payload["tag"])
    ciphertext = bytes.fromhex(payload["ciphertext"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Perform an X25519 key exchange handshake to derive a shared key.
def do_x25519_handshake(sock, is_server):
    local_private_key = X25519PrivateKey.generate()  # Generate local private key
    local_public_key = local_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    if is_server:
        header = recvn(sock, 2)  # Receive client's public key length
        if not header:
            raise ConnectionError("读取客户端公钥长度失败")
        client_pub_len = struct.unpack("!H", header)[0]
        client_public = recvn(sock, client_pub_len)  # Receive client's public key
        if not client_public:
            raise ConnectionError("接收客户端公钥失败")
        sock.sendall(struct.pack("!H", len(local_public_key)) + local_public_key)  # Send our public key
    else:
        sock.sendall(struct.pack("!H", len(local_public_key)) + local_public_key)  # Send our public key
        header = recvn(sock, 2)  # Receive server's public key length
        if not header:
            raise ConnectionError("读取服务器公钥长度失败")
        server_pub_len = struct.unpack("!H", header)[0]
        client_public = recvn(sock, server_pub_len)  # Receive server's public key
        if not client_public:
            raise ConnectionError("接收服务器公钥失败")
    peer_public_key = X25519PublicKey.from_public_bytes(client_public)
    shared_key = local_private_key.exchange(peer_public_key)  # Derive shared key
    return shared_key

# ChatClient handles connection, encryption, and message sending/receiving.
class ChatClient:
    def __init__(self, mode, server_ip, port, ui_callback):
        self.mode = mode
        self.server_ip = server_ip
        self.port = port
        self.sock = None
        self.key = None
        self.stop_event = threading.Event()
        self.ui_callback = ui_callback
        self.send_lock = threading.Lock()
        self.threads = []

    def log(self, msg, tag="info"):
        # Log message to UI via callback.
        self.ui_callback(msg, tag)

    def start(self):
        # Start client/server thread.
        t = threading.Thread(target=self.run, daemon=True)
        t.start()
        self.threads.append(t)

    def run(self):
        # Run as client or server based on mode.
        if self.mode == "c":
            self.run_client()
        else:
            self.run_server()

    def run_client(self):
        reconnect_interval = 5
        while not self.stop_event.is_set():
            try:
                self.log("尝试连接到服务器 {}:{} ...".format(self.server_ip, self.port), "sys")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.server_ip, self.port))
                self.log("已连接到服务器 {}:{}".format(self.server_ip, self.port), "sys")
                self.key = do_x25519_handshake(self.sock, is_server=False)  # Perform handshake
                t_recv = threading.Thread(target=self.receiver, daemon=True)
                t_recv.start()
                self.threads.append(t_recv)
                while not self.stop_event.is_set():
                    time.sleep(0.5)
                break
            except Exception as e:
                self.log("连接/通信异常: {}".format(e), "error")
                if self.sock:
                    try:
                        self.sock.close()
                    except Exception:
                        pass
                self.log("将在 {} 秒后重连...".format(reconnect_interval), "sys")
                time.sleep(reconnect_interval)

    def run_server(self):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(("", self.port))
            server_sock.listen(5)
            self.log("服务器在端口 {} 监听中...".format(self.port), "sys")
            while not self.stop_event.is_set():
                server_sock.settimeout(1.0)
                try:
                    conn, addr = server_sock.accept()
                except socket.timeout:
                    continue
                self.log("接收到来自 {} 的连接".format(addr), "sys")
                try:
                    key = do_x25519_handshake(conn, is_server=True)  # Handshake on connection
                except Exception as e:
                    self.log("握手异常: {}".format(e), "error")
                    conn.close()
                    continue
                t_recv = threading.Thread(target=self.receiver_thread, args=(conn, key), daemon=True)
                t_recv.start()
                self.threads.append(t_recv)
                with self.send_lock:
                    if self.sock:
                        try:
                            self.sock.close()
                        except Exception:
                            pass
                    self.sock = conn
                    self.key = key
            server_sock.close()
        except Exception as e:
            self.log("服务器异常: {}".format(e), "error")

    # Receiving messages in client mode.
    def receiver(self):
        try:
            while not self.stop_event.is_set():
                header = recvn(self.sock, 4)
                if not header:
                    self.log("连接可能已断开", "error")
                    self.stop_event.set()
                    break
                (msg_len,) = struct.unpack("!I", header)
                data = recvn(self.sock, msg_len)
                if not data:
                    self.log("接收数据不完整, 连接断开", "error")
                    self.stop_event.set()
                    break
                try:
                    decrypted = aes_decrypt(self.key, data)  # Decrypt received message
                    self.log("对方: " + decrypted.decode("utf-8"), "peer")
                except Exception as e:
                    self.log("解密异常: " + str(e), "error")
        except Exception as e:
            self.log("接收线程异常: " + str(e), "error")
            self.stop_event.set()
    # Receiving messages in server mode.
    def receiver_thread(self, conn, key):
        try:
            while not self.stop_event.is_set():
                header = recvn(conn, 4)
                if not header:
                    self.log("连接 {} 断开".format(conn.getpeername()), "error")
                    break
                (msg_len,) = struct.unpack("!I", header)
                data = recvn(conn, msg_len)
                if not data:
                    self.log("数据未完整, 连接 {} 关闭".format(conn.getpeername()), "error")
                    break
                try:
                    decrypted = aes_decrypt(key, data)
                    self.log("对方({}): ".format(conn.getpeername()) + decrypted.decode("utf-8"), "peer")
                except Exception as e:
                    self.log("解密异常: " + str(e), "error")
        except Exception as e:
            self.log("接收线程异常: " + str(e), "error")
        finally:
            try:
                conn.close()
            except Exception:
                pass
    # Send a message: encrypt it and then send.
    def send_message(self, message):
        if not self.sock or not self.key:
            self.log("未建立连接", "error")
            return
        try:
            encrypted = aes_encrypt(self.key, message.encode("utf-8"))
            with self.send_lock:
                self.sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)
            self.log("我: " + message, "self")
        except Exception as e:
            self.log("发送异常: " + str(e), "error")

    # Stop all activities.
    def stop(self):
        self.stop_event.set()
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

# ChatGUI manages the graphical user interface.
class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("握手聊天 (AES-GCM)")
        self.ui_queue = queue.Queue()
        self.chat_client = None
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook.Tab", font=("Helvetica", 12, "bold"))
        style.configure("TLabel", font=("Helvetica", 11))
        style.configure("TButton", font=("Helvetica", 11))
        style.configure("TEntry", font=("Helvetica", 11))
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both")
        self.setup_settings_tab()
        self.setup_chat_tab()
        self.root.after(100, self.process_ui_queue)

    # Setup settings tab for configuration.
    def setup_settings_tab(self):
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="设置")
        mode_frame = ttk.LabelFrame(self.settings_frame, text="模式选择")
        mode_frame.pack(fill="x", padx=10, pady=10)
        self.mode_var = tk.StringVar(value="c")
        r_client = ttk.Radiobutton(mode_frame, text="客户端", variable=self.mode_var, value="c", command=self.update_mode)
        r_server = ttk.Radiobutton(mode_frame, text="服务器", variable=self.mode_var, value="s", command=self.update_mode)
        r_client.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        r_server.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        ip_frame = ttk.Frame(self.settings_frame)
        ip_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(ip_frame, text="服务器IP：").grid(row=0, column=0, padx=10, pady=5)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)
        self.ip_entry.insert(0, "127.0.0.1")

        port_frame = ttk.Frame(self.settings_frame)
        port_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(port_frame, text="端口：").grid(row=0, column=0, padx=10, pady=5)
        self.port_entry = ttk.Entry(port_frame)
        self.port_entry.grid(row=0, column=1, padx=10, pady=5)
        self.port_entry.insert(0, "5000")

        btn_frame = ttk.Frame(self.settings_frame)
        btn_frame.pack(fill="x", padx=10, pady=10)
        self.start_btn = ttk.Button(btn_frame, text="开始", command=self.start_network)
        self.start_btn.pack(pady=5)

    # Setup chat tab for messaging.
    def setup_chat_tab(self):
        self.chat_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.chat_frame, text="聊天")

        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, state="disabled", width=80, height=25, font=("Helvetica", 11))
        self.chat_display.tag_config("self", foreground="blue")
        self.chat_display.tag_config("peer", foreground="green")
        self.chat_display.tag_config("sys", foreground="purple", font=("Helvetica", 10, "italic"))
        self.chat_display.tag_config("error", foreground="red", font=("Helvetica", 10, "italic"))
        self.chat_display.pack(padx=10, pady=10, fill="both", expand=True)

        input_frame = ttk.Frame(self.chat_frame)
        input_frame.pack(fill="x", padx=10, pady=5)
        self.msg_entry = ttk.Entry(input_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.msg_entry.bind("<Return>", self.send_msg)
        self.send_btn = ttk.Button(input_frame, text="发送", command=self.send_msg)
        self.send_btn.pack(side="right")

    # Update UI based on selected mode (disable IP field for server).
    def update_mode(self):
        if self.mode_var.get() == "s":
            self.ip_entry.configure(state="disabled")
        else:
            self.ip_entry.configure(state="normal")

    # Start network connection based on settings.
    def start_network(self):
        mode = self.mode_var.get()
        server_ip = self.ip_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("错误", "端口号必须为整数")
            return
        if mode == "c" and not server_ip:
            messagebox.showerror("错误", "客户端模式下请填写服务器IP")
            return
        self.start_btn.configure(state="disabled")
        self.ip_entry.configure(state="disabled")
        self.port_entry.configure(state="disabled")
        for child in self.settings_frame.winfo_children():
            try:
                child.configure(state="disabled")
            except Exception:
                pass
        self.chat_client = ChatClient(mode, server_ip, port, self.ui_put)
        self.chat_client.start()
        self.notebook.select(self.chat_frame)

    # Send message handler bound to UI.
    def send_msg(self, event=None):
        msg = self.msg_entry.get().strip()
        if msg and self.chat_client:
            threading.Thread(target=self.chat_client.send_message, args=(msg,), daemon=True).start()
            self.msg_entry.delete(0, tk.END)

    # Put log messages into a thread-safe UI queue.
    def ui_put(self, msg, tag="info"):
        self.ui_queue.put((msg, tag))

    # Process UI queue to update chat display.
    def process_ui_queue(self):
        while not self.ui_queue.empty():
            try:
                msg, tag = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            self.chat_display.configure(state="normal")
            self.chat_display.insert(tk.END, msg + "\n", tag)
            self.chat_display.configure(state="disabled")
            self.chat_display.see(tk.END)
        self.root.after(100, self.process_ui_queue)

    # Called when closing the application.
    def on_close(self):
        if self.chat_client:
            self.chat_client.stop()
        self.root.destroy()

# Main entry point for the GUI application.
def main():
    root = tk.Tk()
    gui = ChatGUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
