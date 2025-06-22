"""
pip install pycryptodome pynacl
"""

"""
本程序上面没有界面，
下面的程序带有界面黑底红字。
下面的部分，只是上面的部分的界面版本。
希望为您的代码编写，程序设计提供参考，
以及提供一个迷你聊天程序。
"""


import socket
import threading
import os
from Crypto.Cipher import AES
from nacl.public import PrivateKey, PublicKey

# 配置
HOST = 'localhost'
PORT = 65432
def x25519_key_exchange(local_private_key, remote_public_key_bytes):
    remote_public_key = PublicKey(remote_public_key_bytes)
    # 计算共享密钥
    shared_key = local_private_key.exchange(remote_public_key)
    return shared_key
def handle_send(connection, key):
    while True:
        try:
            message = input("Enter message: ").encode()
            nonce = os.urandom(12)  # 随机生成12字节的nonce
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(message)
            connection.sendall(nonce + ciphertext + tag)
        except Exception as e:
            print(f"Error sending message: {e}")
            break
def handle_receive(connection, key):
    while True:
        try:
            data = connection.recv(1024)
            if not data:
                break
            nonce, ciphertext, tag = data[:12], data[12:-16], data[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
            print(f"Received message: {decrypted_message.decode()}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
def start_client():
    client_private_key = PrivateKey.generate()
    client_public_key = client_private_key.public_key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected to server")
        # 交换公钥
        s.sendall(client_public_key.encode())
        server_public_key_bytes = s.recv(32)
        # 计算共享密钥
        shared_key = x25519_key_exchange(client_private_key, server_public_key_bytes)[:32]
        # 启动独立的发送和接收线程
        send_thread = threading.Thread(target=handle_send, args=(s, shared_key))
        receive_thread = threading.Thread(target=handle_receive, args=(s, shared_key))
        send_thread.start()
        receive_thread.start()
        send_thread.join()
        receive_thread.join()

def start_server():
    server_private_key = PrivateKey.generate()
    server_public_key = server_private_key.public_key
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Server listening")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            # 交换公钥
            client_public_key_bytes = conn.recv(32)
            conn.sendall(server_public_key.encode())
            # 计算共享密钥
            shared_key = x25519_key_exchange(server_private_key, client_public_key_bytes)[:32]
            # 启动独立的发送和接收线程
            send_thread = threading.Thread(target=handle_send, args=(conn, shared_key))
            receive_thread = threading.Thread(target=handle_receive, args=(conn, shared_key))
            send_thread.start()
            receive_thread.start()
            send_thread.join()
            receive_thread.join()
if __name__ == "__main__":
    # 根据需求选择启动客户端或服务器
    choice = input("Start as server (s) or client (c)? ").lower()
    if choice == 's':
        start_server()
    elif choice == 'c':
        start_client()
    else:
        print("Invalid choice")













import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import os
import json
import queue
from Crypto.Cipher import AES
from nacl.public import PrivateKey, PublicKey

# 默认配置
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 65432

# 全局变量
socket_connection = None
shared_key = None
stop_threads = False
message_queue = queue.Queue()

def display_message(msg_display, message, sender="Other"):
    global message_queue
    message_queue.put((message, sender))

def process_queue(msg_display):
    global message_queue
    try:
        while True:
            message, sender = message_queue.get_nowait()
            msg_display.configure(state='normal')
            if sender == "Self":
                msg_display.insert(tk.END, f"Me: {message}\n", 'self')
            else:
                msg_display.insert(tk.END, f"Other: {message}\n", 'other')
            msg_display.configure(state='disabled')
            msg_display.see(tk.END)
    except queue.Empty:
        pass
    msg_display.after(100, process_queue, msg_display)

def send_message(msg_input, msg_display):
    global shared_key
    if not shared_key:
        messagebox.showwarning("Warning", "You need to connect first!")
        return

    message = msg_input.get()
    if message:
        display_message(msg_display, message, sender="Self")
        threading.Thread(target=send_encrypted_message, args=(message,)).start()
        msg_input.set("")

def send_encrypted_message(message):
    global socket_connection, shared_key
    try:
        nonce = os.urandom(12)
        cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())

        message_packet = {
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex()
        }
        message_json = json.dumps(message_packet).encode() + b'\n'
        socket_connection.sendall(message_json)
    except Exception as e:
        messagebox.showerror("Send Error", f"Error sending message: {e}")

def receive_messages(msg_display):
    global socket_connection, stop_threads, shared_key
    buffer = b''
    while not stop_threads:
        try:
            data = socket_connection.recv(1024)
            if not data:
                break
            buffer += data
            while b'\n' in buffer:
                line_end = buffer.index(b'\n')
                message_json = buffer[:line_end]
                buffer = buffer[line_end + 1:]
                message_data = json.loads(message_json.decode())
                nonce = bytes.fromhex(message_data['nonce'])
                ciphertext = bytes.fromhex(message_data['ciphertext'])
                tag = bytes.fromhex(message_data['tag'])
                cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
                display_message(msg_display, decrypted_message.decode(), sender="Other")
        except Exception as e:
            if not stop_threads:
                messagebox.showerror("Receive Error", f"Error receiving message: {e}")
            break
def setup_connection(host, port, is_server=False):
    global socket_connection, shared_key
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    if is_server:
        socket_connection.listen()
        conn, addr = socket_connection.accept()
        socket_connection = conn
        client_public_key_bytes = socket_connection.recv(32)
        socket_connection.sendall(public_key.encode())
        shared_key = private_key.exchange(PublicKey(client_public_key_bytes))[:32]
    else:
        socket_connection.connect((host, port))
        socket_connection.sendall(public_key.encode())
        server_public_key_bytes = socket_connection.recv(32)
        shared_key = private_key.exchange(PublicKey(server_public_key_bytes))[:32]
    messagebox.showinfo("Connection Status", "Connection established successfully!")

def start_client(host, port, msg_display):
    global socket_connection
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        setup_connection(host, port, is_server=False)
        threading.Thread(target=receive_messages, args=(msg_display,), daemon=True).start()
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect as a client: {e}")

def start_server(host, port, msg_display):
    global socket_connection
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.bind((host, port))
        setup_connection(host, port, is_server=True)
        threading.Thread(target=receive_messages, args=(msg_display,), daemon=True).start()
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to start as a server: {e}")

def on_close(root):
    global stop_threads, socket_connection
    stop_threads = True
    if socket_connection:
        socket_connection.close()
    root.destroy()

def create_ui():
    root = tk.Tk()
    root.title("Secure Chat")
    root.geometry("600x400")
    root.configure(bg='black')
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('TNotebook', background='black')
    style.configure('TFrame', background='black')
    style.configure('TLabel', background='white', foreground='white')
    style.configure('TEntry', fieldbackground='black', foreground='white')
    style.configure('TButton', background='gray', foreground='white')
    style.configure('TNotebook.Tab', background='black', foreground='white')
    tab_control = ttk.Notebook(root)
    chat_frame = ttk.Frame(tab_control)
    connection_frame = ttk.Frame(tab_control)
    tab_control.add(chat_frame, text='Chat')
    tab_control.add(connection_frame, text='Connection')
    tab_control.pack(expand=1, fill="both")
    msg_display = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, state='disabled', bg='black', fg='white')
    msg_display.tag_configure('self', foreground='red')
    msg_display.tag_configure('other', foreground='green')
    msg_display.pack(expand=1, fill='both')
    msg_input_frame = ttk.Frame(chat_frame)
    msg_input_frame.pack(fill='x', padx=5, pady=5)
    msg_input = tk.StringVar()
    msg_entry = ttk.Entry(msg_input_frame, textvariable=msg_input)
    msg_entry.pack(side=tk.LEFT, expand=1, fill='x')
    send_button = ttk.Button(msg_input_frame, text="Send", command=lambda: send_message(msg_input, msg_display))
    send_button.pack(side=tk.RIGHT)
    ttk.Label(connection_frame, text="Host:").grid(column=0, row=0, padx=5, pady=5)
    host_var = tk.StringVar(value=DEFAULT_HOST)
    host_entry = ttk.Entry(connection_frame, textvariable=host_var)
    host_entry.grid(column=1, row=0, padx=5, pady=5)
    ttk.Label(connection_frame, text="Port:").grid(column=0, row=1, padx=5, pady=5)
    port_var = tk.IntVar(value=DEFAULT_PORT)
    port_entry = ttk.Entry(connection_frame, textvariable=port_var)
    port_entry.grid(column=1, row=1, padx=5, pady=5)
    connect_button = ttk.Button(connection_frame, text="Connect as Client",
                                command=lambda: threading.Thread(target=start_client, args=(host_var.get(), port_var.get(), msg_display)).start())
    connect_button.grid(column=0, row=2, padx=5, pady=5, columnspan=2)
    server_button = ttk.Button(connection_frame, text="Start as Server",
                               command=lambda: threading.Thread(target=start_server, args=(host_var.get(), port_var.get(), msg_display)).start())
    server_button.grid(column=0, row=3, padx=5, pady=5, columnspan=2)
    process_queue(msg_display)
    root.protocol("WM_DELETE_WINDOW", lambda: on_close(root))
    return root
if __name__ == "__main__":
    app = create_ui()
    app.mainloop()
