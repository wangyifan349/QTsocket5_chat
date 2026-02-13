import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import time
# 使用密码生成 AES 密钥
def generate_aes_key_from_password(password):
    # 生成一个随机盐值
    salt = os.urandom(16)
    
    # 使用 PBKDF2HMAC 生成 AES 密钥
    # 设置生成 128 位 AES 密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,  # AES 密钥的长度（128 位）
        salt=salt,  # 盐值
        iterations=100000,  # 迭代次数（100000 次）
        backend=default_backend()
    )
    # 根据密码生成 AES 密钥
    key = kdf.derive(password.encode())  
    return key, salt
from datetime import datetime
# 获取当前的时间戳（标准时间），并将其格式化为易读的字符串，作为 AAD
def get_current_timestamp():
    # 获取当前时间并格式化为 'YYYY-MM-DD HH:MM:SS' 格式
    current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    return current_time  # 返回格式化后的标准时间字符串
# 加密文件
def encrypt_file(input_file_path, aes_key):
    try:
        # 创建 AESGCM 加密对象
        aesgcm = AESGCM(aes_key)
        # 生成 12 字节的随机 nonce（初始化向量）
        nonce = os.urandom(12)
        # 获取当前时间戳，并将其作为 AAD（认证但未加密的数据）
        aad = get_current_timestamp().encode()
        # 读取文件内容并进行加密
        with open(input_file_path, 'rb') as input_file:
            data = input_file.read()  # 读取整个文件的二进制数据
        # 加密数据，返回加密后的密文
        ciphertext = aesgcm.encrypt(nonce, data, aad)  # 加密过程
        # 将 nonce、AAD 和密文写入文件
        with open(input_file_path, 'wb') as output_file:
            output_file.write(nonce + aad + ciphertext)  # 写入 nonce、时间戳（AAD）和密文
        return f"Encrypted: {input_file_path}"  # 返回加密完成的信息
    except Exception as e:
        return f"Error encrypting {input_file_path}: {str(e)}"  # 错误处理

# 解密文件
def decrypt_file(input_file_path, aes_key):
    try:
        # 创建 AESGCM 解密对象
        aesgcm = AESGCM(aes_key)
        
        # 读取文件内容：首先读取 nonce 和 AAD，再读取密文部分
        with open(input_file_path, 'rb') as input_file:
            nonce = input_file.read(12)  # 读取 12 字节的 nonce
            aad = input_file.read(10)  # 读取 10 字节的时间戳（AAD）
            print(aad)
            ciphertext = input_file.read()  # 读取剩余的密文数据
        # 使用读取到的 nonce 和 AAD 解密密文
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, aad)  # 解密过程
        # 将解密后的数据直接覆盖到原文件中
        with open(input_file_path, 'wb') as output_file:
            output_file.write(decrypted_data)  # 写入解密后的数据
        return f"Decrypted: {input_file_path}"  # 返回解密完成的信息
    except Exception as e:
        return f"Error decrypting {input_file_path}: {str(e)}"  # 错误处理

# 批量加密目录中的所有文件
def encrypt_directory(input_dir, aes_key):
    results = []  # 用于存储加密结果
    for root, dirs, files in os.walk(input_dir):  # 遍历目录中的所有文件
        for file_name in files:
            input_file_path = os.path.join(root, file_name)
            result = encrypt_file(input_file_path, aes_key)  # 加密每个文件
            results.append(result)  # 将结果添加到结果列表中
    return results

# 批量解密目录中的所有文件
def decrypt_directory(input_dir, aes_key):
    results = []  # 用于存储解密结果
    for root, dirs, files in os.walk(input_dir):  # 遍历目录中的所有文件
        for file_name in files:
            input_file_path = os.path.join(root, file_name)
            result = decrypt_file(input_file_path, aes_key)  # 解密每个文件
            results.append(result)  # 将结果添加到结果列表中
    return results
# 交互式菜单
def menu():
    print("AES Encryption & Decryption Tool\n")
    # 获取用户输入的密码，并使用密码生成 AES 密钥
    password = input("Enter your password to generate AES key: ").strip()
    aes_key, salt = generate_aes_key_from_password(password)  # 生成 AES 密钥
    while True:
        print("\nPlease choose an option:")
        print("1. Encrypt files in a directory")  # 加密文件
        print("2. Decrypt files in a directory")  # 解密文件
        print("3. Exit")  # 退出程序
        # 获取用户选择
        choice = input("Enter your choice (1/2/3): ").strip()
        if choice == '1':
            # 获取待加密目录路径，并对目录中的所有文件进行加密
            input_dir = input("Enter directory to encrypt: ").strip()
            results = encrypt_directory(input_dir, aes_key)
            for result in results:
                print(result)  # 输出加密结果
        elif choice == '2':
            # 获取待解密目录路径，并对目录中的所有文件进行解密
            input_dir = input("Enter directory to decrypt: ").strip()
            results = decrypt_directory(input_dir, aes_key)
            for result in results:
                print(result)  # 输出解密结果
        elif choice == '3':
            print("Exiting...")  # 退出程序
            break  # 退出循环，结束程序
        
        else:
            print("Invalid choice. Please try again.")  # 输入无效时提示
menu()  # 启动交互式菜单
