import socket
import threading
from nacl.public import PrivateKey, PublicKey, Box
import hashlib
from cryptography.hazmat.primitives import hashes
# Generate client's private and public keys
client_private_key = PrivateKey.generate()
client_public_key = client_private_key.public_key
# Setup TCP client
HOST = '127.0.0.1'
PORT = 12345

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
# Send client's public key to the server
client.send(client_public_key.encode())
# Receive server's public key
server_public_key_data = client.recv(1024)
server_public_key = PublicKey(server_public_key_data)
# Generate shared secret using X25519
client_box = Box(client_private_key, server_public_key)
# Function to handle sending chat messages
def send_chat():
    while True:
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break
        encrypted_message = client_box.encrypt(message.encode())
        client.send(encrypted_message)

# Function to handle receiving chat messages
def receive_chat():
    while True:
        encrypted_message = client.recv(1024)
        if encrypted_message:
            decrypted_message = client_box.decrypt(encrypted_message)
            print(f"Server replied: {decrypted_message.decode()}")

# Function to send a file securely in chunks
def send_file(filename):
    with open(filename, 'rb') as f:
        file_data = f.read()
    # Encrypt file data and send in chunks
    for i in range(0, len(file_data), 1024):
        chunk = file_data[i:i+1024]
        encrypted_chunk = client_box.encrypt(chunk)
        client.send(encrypted_chunk)
    print(f"File {filename} sent successfully.")
# Function to calculate file hash (SHA256) for integrity check
def file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()
# Start chat receiving thread
chat_receive_thread = threading.Thread(target=receive_chat)
chat_receive_thread.start()
# Start chat sending thread
chat_send_thread = threading.Thread(target=send_chat)
chat_send_thread.start()
# Continuous file sending functionality
while True:
    file_to_send = input("Enter filename to send (or 'exit' to quit): ")
    if file_to_send.lower() == 'exit':
        break
    try:
        send_file(file_to_send)
    except FileNotFoundError:
        print(f"File {file_to_send} not found.")
        continue
    # After file transfer, prompt the user to continue chatting
    continue_chat = input("Do you want to continue chatting (y/n)? ")
    if continue_chat.lower() != 'y':
        break
client.close()
