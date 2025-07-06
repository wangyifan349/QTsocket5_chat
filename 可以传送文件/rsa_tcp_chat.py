import socket
import threading
import os
import sys
import json
import hashlib
import time
import base58  # 用于 Base58 编码
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
# ======================= 全局变量和初始化 =======================
# 全局变量
server_socket = None
client_socket = None
aes_key = None
is_running = True
send_queue = []
receive_queue = []
lock = threading.Lock()
# 在程序启动时生成 RSA 密钥对
key = RSA.generate(2048)
private_key_pem = key.export_key()
public_key_pem = key.publickey().export_key()
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] RSA 密钥对已生成。")
# 获取当前时间的字符串表示
def get_current_time():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
# 打印带有时间戳的状态消息
def print_status(message):
    print(f"[{get_current_time()}] {message}")
# 创建一个包含类型和负载的 JSON 字符串
def create_packet(packet_type, payload):
    packet = {'type': packet_type}
    packet.update(payload)
    return json.dumps(packet)
# 解析 JSON 格式的消息包
def parse_packet(json_bytes):
    try:
        packet = json.loads(json_bytes.decode('utf-8'))
        return packet
    except json.JSONDecodeError:
        print_status("无法解析收到的 JSON 数据。")
        return None
# 计算文件的 SHA256 哈希值
def calculate_file_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # 读取 64KB
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()
# 使用 Base58 编码数据
def encode_base58(data_bytes):
    return base58.b58encode(data_bytes).decode('utf-8')
# 使用 Base58 解码数据
def decode_base58(data_str):
    try:
        return base58.b58decode(data_str.encode('utf-8'))
    except ValueError:
        print_status("Base58 解码失败，数据可能被篡改。")
        return None
# 使用接收方的 RSA 公钥加密 AES 密钥
def encrypt_aes_key_with_rsa(aes_key, recipient_public_key_pem):
    recipient_public_key = RSA.import_key(recipient_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key
# 使用自己的 RSA 私钥解密 AES 密钥
def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key
# 使用 AES-GCM 模式加密消息
def encrypt_message(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    encrypted_data = {
        'nonce': encode_base58(cipher.nonce),
        'ciphertext': encode_base58(ciphertext),
        'tag': encode_base58(tag)
    }
    return json.dumps(encrypted_data).encode('utf-8')
# 使用 AES-GCM 模式解密消息
def decrypt_message(aes_key, encrypted_data_bytes):
    try:
        encrypted_data = json.loads(encrypted_data_bytes.decode('utf-8'))
        nonce = decode_base58(encrypted_data['nonce'])
        ciphertext = decode_base58(encrypted_data['ciphertext'])
        tag = decode_base58(encrypted_data['tag'])
        if nonce is None or ciphertext is None or tag is None:
            return None
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext_bytes.decode('utf-8')
    except (ValueError, KeyError, json.JSONDecodeError):
        print_status("解密消息时发生错误，可能是数据被篡改。")
        return None
# 接收固定长度的数据
def receive_fixed_length_data(sock, length):
    data = b''
    while len(data) < length:
        try:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        except socket.error:
            return None
    return data
# 发送数据（使用 Base58 编码）
def send_data(sock, data_bytes):
    encoded_data = encode_base58(data_bytes).encode('utf-8')
    data_length = len(encoded_data)
    sock.sendall(data_length.to_bytes(4, 'big') + encoded_data)
# 接收数据（使用 Base58 解码）
def receive_data(sock):
    length_bytes = receive_fixed_length_data(sock, 4)
    if not length_bytes:
        return None
    data_length = int.from_bytes(length_bytes, 'big')
    encoded_data = receive_fixed_length_data(sock, data_length)
    if not encoded_data:
        return None
    data_bytes = decode_base58(encoded_data.decode('utf-8'))
    return data_bytes
# ======================= 服务器功能 =======================
def start_server(port):
    global server_socket, is_running
    # 创建服务器套接字
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print_status(f"服务器正在监听端口 {port}...")
    while is_running:
        # 接受客户端连接
        try:
            client_sock, client_addr = server_socket.accept()
            print_status(f"接受来自 {client_addr} 的连接。")
            # 创建新的线程处理客户端连接
            threading.Thread(target=handle_client, args=(client_sock, client_addr)).start()
        except KeyboardInterrupt:
            print_status("服务器正在关闭...")
            is_running = False
            server_socket.close()
            break
def handle_client(sock, addr):
    global is_running
    client_aes_key = None
    file_receiving = False
    file_info = {}
    file_data = b''
    try:
        # 发送服务器的公钥给客户端
        send_data(sock, public_key_pem)
        print_status(f"已发送公钥给客户端 {addr}。")
        # 接收客户端的公钥
        client_public_key_pem = receive_data(sock)
        if not client_public_key_pem:
            print_status(f"无法接收客户端 {addr} 的公钥。")
            sock.close()
            return
        print_status(f"已接收客户端 {addr} 的公钥。")
        # 生成 AES 密钥并加密发送给客户端
        client_aes_key = get_random_bytes(32)
        encrypted_aes_key = encrypt_aes_key_with_rsa(client_aes_key, client_public_key_pem)
        send_data(sock, encrypted_aes_key)
        print_status(f"已发送加密的 AES 密钥给客户端 {addr}。")
        # 启动接收线程
        threading.Thread(target=server_receive_loop, args=(sock, addr, client_aes_key)).start()
    except Exception as e:
        print_status(f"处理客户端 {addr} 时发生错误：{e}")
        sock.close()
def server_receive_loop(sock, addr, client_aes_key):
    global is_running
    file_receiving = False
    file_info = {}
    file_data = b''
    while is_running:
        try:
            # 接收加密的数据
            encrypted_data = receive_data(sock)
            if not encrypted_data:
                print_status(f"客户端 {addr} 已断开连接。")
                break
            # 解密数据
            message = decrypt_message(client_aes_key, encrypted_data)
            if message is None:
                continue  # 解密失败，可能是数据篡改，继续接收下一条消息
            # 解析消息
            packet = parse_packet(message.encode('utf-8'))
            if packet is None:
                continue
            packet_type = packet.get('type')
            if packet_type == 'text':
                content = packet.get('content', '')
                print(f"\r[{get_current_time()}][客户端 {addr}]: {content}\n>>> ", end='')
            elif packet_type == 'file_info':
                # 准备接收文件
                filename = 'received_' + packet.get('filename', 'unknown')
                filesize = packet.get('filesize', 0)
                sha256 = packet.get('sha256', '')
                file_receiving = True
                file_info = {'filename': filename, 'filesize': filesize, 'sha256': sha256}
                file_data = b''
                print_status(f"准备接收来自 {addr} 的文件：{filename}，大小：{filesize} 字节。")
            elif packet_type == 'file_chunk':
                if not file_receiving:
                    print_status(f"未接收到文件信息，无法处理文件块。")
                    continue
                # 接收文件块
                chunk_data = decode_base58(packet.get('data', ''))
                if chunk_data is None:
                    print_status(f"解码文件块时发生错误。")
                    continue
                file_data += chunk_data
                if len(file_data) >= file_info['filesize']:
                    # 文件接收完毕，校验哈希
                    received_sha256 = hashlib.sha256(file_data).hexdigest()
                    if received_sha256 == file_info['sha256']:
                        # 保存文件
                        with open(file_info['filename'], 'wb') as f:
                            f.write(file_data)
                        print_status(f"文件 {file_info['filename']} 接收完成并已保存。")
                    else:
                        print_status(f"文件 {file_info['filename']} 校验失败，文件可能已损坏。")
                    file_receiving = False
            else:
                print_status(f"收到未知类型的消息：{packet_type}")
        except Exception as e:
            print_status(f"与客户端 {addr} 通信时发生错误：{e}")
            break
    sock.close()
# ======================= 客户端功能 =======================
def start_client(server_ip, server_port):
    global client_socket, aes_key, is_running, send_queue
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # 连接服务器
        client_socket.connect((server_ip, server_port))
        print_status(f"已连接到服务器 {server_ip}:{server_port}")
        # 接收服务器的公钥
        server_public_key_pem = receive_data(client_socket)
        if not server_public_key_pem:
            print_status("无法接收服务器的公钥。")
            client_socket.close()
            return
        print_status("已接收服务器的公钥。")
        # 发送客户端的公钥给服务器
        send_data(client_socket, public_key_pem)
        print_status("已发送公钥给服务器。")
        # 接收加密的 AES 密钥并解密
        encrypted_aes_key = receive_data(client_socket)
        if not encrypted_aes_key:
            print_status("无法接收加密的 AES 密钥。")
            client_socket.close()
            return
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem)
        print_status("已接收并解密 AES 密钥。")
        # 启动发送和接收线程
        threading.Thread(target=client_send_loop).start()
        threading.Thread(target=client_receive_loop).start()
    except Exception as e:
        print_status(f"连接服务器时发生错误：{e}")
        client_socket.close()
        return
def client_send_loop():
    global is_running, send_queue, aes_key, client_socket
    while is_running:
        try:
            if send_queue:
                message = send_queue.pop(0)
                encrypted_data = encrypt_message(aes_key, message)
                send_data(client_socket, encrypted_data)
            else:
                time.sleep(0.1)
        except Exception as e:
            print_status(f"发送消息时发生错误：{e}")
            break
    client_socket.close()
def client_receive_loop():
    global is_running, aes_key, client_socket
    while is_running:
        try:
            # 接收加密的数据
            encrypted_data = receive_data(client_socket)
            if not encrypted_data:
                print_status("服务器已断开连接。")
                break
            # 解密数据
            message = decrypt_message(aes_key, encrypted_data)
            if message is None:
                continue  # 解密失败，可能是数据篡改，继续接收下一条消息
            # 打印消息
            print(f"\r{message}\n>>> ", end='')
        except Exception as e:
            print_status(f"接收消息时发生错误：{e}")
            break
    client_socket.close()
# ======================= 主程序 =======================
def main():
    global is_running, send_queue
    print("请选择模式：")
    print("1 - 运行服务器")
    print("2 - 连接到服务器（客户端）")
    choice = input("请输入选项（1或2）：").strip()
    if choice == '1':
        # 启动服务器
        try:
            port_input = input("请输入服务器端口（默认12345）：").strip()
            port = int(port_input) if port_input else 12345
        except ValueError:
            port = 12345
        threading.Thread(target=start_server, args=(port,)).start()
    elif choice == '2':
        # 启动客户端
        server_ip = input("请输入服务器 IP 地址：").strip()
        try:
            port_input = input("请输入服务器端口（默认12345）：").strip()
            server_port = int(port_input) if port_input else 12345
        except ValueError:
            server_port = 12345
        threading.Thread(target=start_client, args=(server_ip, server_port)).start()
        # 等待连接建立
        time.sleep(2)
        if not client_socket:
            print_status("无法连接到服务器。")
            return
        print_status("您可以开始聊天，输入 'exit' 退出，输入 '/sendfile <文件路径>' 发送文件。")
        while is_running:
            user_input = input(">>> ").strip()
            if user_input.lower() == 'exit':
                is_running = False
                break
            elif user_input.startswith('/sendfile '):
                filepath = user_input[10:].strip()
                if os.path.isfile(filepath):
                    try:
                        # 读取文件信息
                        filesize = os.path.getsize(filepath)
                        filename = os.path.basename(filepath)
                        sha256_hash = calculate_file_sha256(filepath)
                        # 发送文件信息
                        file_info_packet = create_packet('file_info', {
                            'filename': filename,
                            'filesize': filesize,
                            'sha256': sha256_hash
                        })
                        send_queue.append(file_info_packet)
                        # 发送文件内容
                        with open(filepath, 'rb') as f:
                            while True:
                                data = f.read(65536)  # 每次读取64KB
                                if not data:
                                    break
                                data_base58 = encode_base58(data)
                                file_chunk_packet = create_packet('file_chunk', {'data': data_base58})
                                send_queue.append(file_chunk_packet)
                        print_status(f"文件 '{filename}' 已发送。")
                    except Exception as e:
                        print_status(f"发送文件时发生错误：{e}")
                else:
                    print_status("文件不存在，请检查文件路径。")
            else:
                if user_input:
                    # 发送文本消息
                    packet = create_packet('text', {'content': user_input})
                    send_queue.append(packet)
    else:
        print("无效的选择，程序将退出。")
        is_running = False
        return

    # 等待程序结束
    try:
        while is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        is_running = False
        print_status("程序正在关闭...")

if __name__ == '__main__':
    main()
