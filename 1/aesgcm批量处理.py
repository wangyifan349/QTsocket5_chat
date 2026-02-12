import os
import curses
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
# 使用密码生成 AES 密钥
def generate_aes_key_from_password(password):
    # 使用 PBKDF2 从密码生成 AES 密钥
    salt = os.urandom(16)  # 生成随机盐，确保相同密码每次生成的密钥不同
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 位密钥
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(password.encode())  # 使用密码生成密钥
    return aes_key, salt
# 加密单个文件
def encrypt_file(input_file_path, output_file_path, aes_key):
    # 生成一个随机的 nonce（对于 AES-GCM 至少 12 字节）
    nonce = os.urandom(12)
    # 初始化 AES 加密器
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_file_path, 'rb') as input_file:
        # 创建输出文件，并写入 nonce 和 tag
        with open(output_file_path, 'wb') as output_file:
            # 先写入 nonce
            output_file.write(nonce)
            # 加密文件内容
            while chunk := input_file.read(4096):  # 以 4KB 为单位加密文件
                ciphertext = encryptor.update(chunk)
                output_file.write(ciphertext)
            
            # 写入 GCM tag
            tag = encryptor.finalize()
            output_file.write(tag)

    return f"Encrypted file saved as {output_file_path}"
# 解密单个文件
def decrypt_file(input_file_path, output_file_path, aes_key):
    with open(input_file_path, 'rb') as input_file:
        # 读取 nonce
        nonce = input_file.read(12)
        # 初始化 AES 解密器
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        with open(output_file_path, 'wb') as output_file:
            # 读取并解密文件内容
            while chunk := input_file.read(4096 + 16):  # GCM 的 tag 长度是 16 字节
                if len(chunk) < 16:
                    # 如果剩余的数据小于 tag 长度，直接跳出
                    break
                ciphertext = chunk[:-16]  # 去掉 tag 部分
                output_file.write(decryptor.update(ciphertext))
            # 获取并验证 tag
            tag = chunk[-16:]  # 取出最后的 16 字节作为 tag
            decryptor.finalize_with_tag(tag)
    return f"Decrypted file saved as {output_file_path}"
# 批量加密
def encrypt_directory(input_dir, output_dir, aes_key):
    # 遍历目录及其子目录，生成文件列表
    files_to_encrypt = []
    for root, dirs, files in os.walk(input_dir):
        for file_name in files:
            input_file_path = os.path.join(root, file_name)
            # 生成输出文件路径
            relative_path = os.path.relpath(input_file_path, input_dir)
            output_file_path = os.path.join(output_dir, relative_path)
            files_to_encrypt.append((input_file_path, output_file_path))

    # 使用 ThreadPoolExecutor 来并行处理文件
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda p: encrypt_file(p[0], p[1], aes_key), files_to_encrypt))
    return results
# 批量解密
def decrypt_directory(input_dir, output_dir, aes_key):
    # 遍历目录及其子目录，生成文件列表
    files_to_decrypt = []
    for root, dirs, files in os.walk(input_dir):
        for file_name in files:
            input_file_path = os.path.join(root, file_name)
            # 生成输出文件路径
            relative_path = os.path.relpath(input_file_path, input_dir)
            output_file_path = os.path.join(output_dir, relative_path)
            files_to_decrypt.append((input_file_path, output_file_path))
    # 使用 ThreadPoolExecutor 来并行处理文件
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda p: decrypt_file(p[0], p[1], aes_key), files_to_decrypt))
    return results
# 交互式菜单
def menu(stdscr):
    # 清屏
    stdscr.clear()
    # 输入密码生成 AES 密钥
    stdscr.addstr(0, 0, "AES Encryption & Decryption Tool")
    stdscr.addstr(2, 0, "Enter your password to generate AES key: ")
    stdscr.refresh()
    password = stdscr.getstr().decode("utf-8")  # 获取用户输入的密码
    # 生成 AES 密钥和盐值
    aes_key, salt = generate_aes_key_from_password(password)
    while True:
        stdscr.clear()
        stdscr.addstr(4, 0, "1. Encrypt files in a directory")
        stdscr.addstr(5, 0, "2. Decrypt files in a directory")
        stdscr.addstr(6, 0, "3. Exit")
        stdscr.addstr(8, 0, "Please choose an option (1/2/3): ")
        stdscr.refresh()
        choice = stdscr.getch()
        if choice == ord('1'):
            # 输入加密目录
            stdscr.addstr(10, 0, "Enter directory to encrypt: ")
            stdscr.refresh()
            input_dir = stdscr.getstr().decode("utf-8")
            # 输入输出目录
            stdscr.addstr(11, 0, "Enter output directory for encrypted files: ")
            stdscr.refresh()
            output_dir = stdscr.getstr().decode("utf-8")
            # 执行加密
            results = encrypt_directory(input_dir, output_dir, aes_key)
            for result in results:
                stdscr.addstr(13, 0, result)
                stdscr.refresh()
        elif choice == ord('2'):
            # 输入解密目录
            stdscr.addstr(10, 0, "Enter directory to decrypt: ")
            stdscr.refresh()
            input_dir = stdscr.getstr().decode("utf-8")
            # 输入输出目录
            stdscr.addstr(11, 0, "Enter output directory for decrypted files: ")
            stdscr.refresh()
            output_dir = stdscr.getstr().decode("utf-8")
            # 执行解密
            results = decrypt_directory(input_dir, output_dir, aes_key)
            for result in results:
                stdscr.addstr(13, 0, result)
                stdscr.refresh()
        elif choice == ord('3'):
            break
# 启动交互式菜单
if __name__ == "__main__":
    curses.wrapper(menu)
