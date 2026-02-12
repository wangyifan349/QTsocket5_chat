import socket
import threading
import hashlib
from nacl.public import PrivateKey, PublicKey, Box
import nacl.utils

# Generate server's private and public keys
server_private_key = PrivateKey.generate()
server_public_key = server_private_key.public_key

# Setup TCP server
HOST = '127.0.0.1'
PORT = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)
print(f"Server listening on {HOST}:{PORT}")

conn, addr = server.accept()
print(f"Connection established with {addr}")

# Exchange public keys with client
client_public_key_data = conn.recv(1024)
client_public_key = PublicKey(client_public_key_data)

# Generate shared secret using X25519
server_box = Box(server_private_key, client_public_key)

# Send server's public key to the client
conn.send(server_public_key.encode())

# Function to receive and decrypt file in chunks
def receive_file():
    received_file = b""
    while True:
        encrypted_chunk = conn.recv(1024)
        if not encrypted_chunk:
            break  # If no more data, end the file transfer
        decrypted_chunk = server_box.decrypt(encrypted_chunk)
        received_file += decrypted_chunk
    return received_file

# Function to save the received file
def save_file(file_data, filename):
    with open(filename, 'wb') as f:
        f.write(file_data)
    print(f"File saved as {filename}")

# Function to calculate file hash (SHA256) for integrity check
def file_hash(file_data):
    return hashlib.sha256(file_data).hexdigest()

# Function to handle receiving chat messages
def receive_chat():
    while True:
        encrypted_message = conn.recv(1024)
        if encrypted_message:
            decrypted_message = server_box.decrypt(encrypted_message)
            print(f"Received message: {decrypted_message.decode()}")

# Function to handle sending chat messages
def send_chat():
    while True:
        message = input("Enter message to send: ")
        if message.lower() == 'exit':
            break
        encrypted_message = server_box.encrypt(message.encode())
        conn.send(encrypted_message)

# Start chat receiving thread
chat_receive_thread = threading.Thread(target=receive_chat)
chat_receive_thread.start()

# Start chat sending thread
chat_send_thread = threading.Thread(target=send_chat)
chat_send_thread.start()

# Continuous file transfer and chat functionality
while True:
    print("Waiting for file transfer...")
    received_file = receive_file()
    file_hash_value = file_hash(received_file)
    print(f"Received file hash: {file_hash_value}")
    save_file(received_file, "received_file")
    
    # After file transfer, prompt the user to continue chatting
    continue_chat = input("Do you want to continue chatting (y/n)? ")
    if continue_chat.lower() != 'y':
        break

# Close the connection
conn.close()
server.close()
