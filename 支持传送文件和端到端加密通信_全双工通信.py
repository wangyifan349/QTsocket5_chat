import socket
import threading
import os
import argparse
from coincurve import PrivateKey, PublicKey
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20_Poly1305

# Default server configuration
SERVER_HOST = '0.0.0.0'  # Server listening address
SERVER_PORT = 5555       # Server port
CLIENT_HOST = '127.0.0.1'  # Default client address
CLIENT_PORT = 5555      # Default client port

MAX_CHUNK_SIZE = 1024 * 1024  # 1MB per file chunk

# Derive shared key from ECDH using private key and peer's public key
def derive_shared_key(private_key: PrivateKey, peer_public_key_bytes: bytes) -> bytes:
    peer_public_key = PublicKey(peer_public_key_bytes)
    shared_secret = private_key.ecdh(peer_public_key)  # ECDH point multiplication
    return HKDF(shared_secret, 32, b'', SHA256)  # Derive symmetric key using HKDF

# ECDH handshake to exchange public keys and generate a shared secret
def handshake(connection):
    private_key = PrivateKey()
    peer_public_key_bytes = connection.recv(33)  # Receive peer's public key (33 bytes)
    connection.send(private_key.public_key.format(compressed=True))  # Send own public key
    return derive_shared_key(private_key, peer_public_key_bytes)  # Derive shared key

# Encrypt data using ChaCha20-Poly1305
def encrypt(key, data):
    cipher = ChaCha20_Poly1305.new(key=key)
    return cipher.nonce + cipher.encrypt(data) + cipher.digest()  # Return nonce + encrypted data + tag

# Decrypt data using ChaCha20-Poly1305
def decrypt(key, data):
    nonce, encrypted_data_with_tag = data[:12], data[12:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = encrypted_data_with_tag[:-16], encrypted_data_with_tag[-16:]  # Separate ciphertext and tag
    return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify the tag

# Function to send a file in chunks
def send_file(connection, filename, key):
    try:
        with open(filename, "rb") as file:
            file_size = os.path.getsize(filename)
            total_chunks = (file_size // MAX_CHUNK_SIZE) + (1 if file_size % MAX_CHUNK_SIZE else 0)
            print(f"Sending file: {filename} ({file_size} bytes), {total_chunks} chunks.")

            for i in range(total_chunks):
                chunk_data = file.read(MAX_CHUNK_SIZE)  # Read a chunk
                encrypted_chunk = encrypt(key, chunk_data)
                connection.send(f"FILE_CHUNK {i + 1}/{total_chunks}".encode())  # Send chunk info
                connection.send(encrypted_chunk)  # Send encrypted chunk
            print(f"File {filename} sent successfully.")
    except Exception as e:
        print(f"Error sending file {filename}: {e}")

# Function to receive a file
def receive_file(connection, filename, key):
    try:
        with open(filename, "wb") as file:
            while True:
                chunk_info = connection.recv(1024).decode()  # Receive chunk info (e.g., FILE_CHUNK 1/5)
                if not chunk_info:
                    break
                print(f"Receiving {chunk_info}...")
                chunk_data = connection.recv(1024 * 1024)  # Receive up to 1MB per chunk
                decrypted_chunk = decrypt(key, chunk_data)  # Decrypt the chunk
                file.write(decrypted_chunk)  # Write the chunk to file
            print(f"File {filename} received successfully.")
    except Exception as e:
        print(f"Error receiving file {filename}: {e}")

# Thread to receive messages from the other party (server or client)
def receive_thread(connection, key):
    while True:
        try:
            data = connection.recv(4096)
            if not data:
                break
            message = decrypt(key, data).decode()
            if message.startswith("SEND_FILE"):
                filename = message.split(" ")[1]
                print(f"Ready to receive file: {filename}")
                receive_file(connection, filename, key)  # Receive the file
            else:
                print("\nReceived:", message)  # Print regular messages
        except Exception as e:
            print("Receive Error:", e)
            break

# Thread to send messages or files to the other party (server or client)
def send_thread(connection, key):
    while True:
        message = input()
        if message.startswith("SEND_FILE"):
            filename = message.split(" ")[1]
            print(f"Sending file: {filename}")
            send_file(connection, filename, key)  # Send the file
        else:
            encrypted_message = encrypt(key, message.encode())  # Encrypt and send the message
            connection.send(encrypted_message)

# Server mode: Listens for a connection, performs handshake, and starts communication
def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}...")

    connection, _ = server_socket.accept()  # Accept client connection
    print("Connection established.")
    shared_key = handshake(connection)  # Perform handshake and generate shared key
    print("Shared key established.")

    # Start threads for receiving and sending messages
    t1 = threading.Thread(target=receive_thread, args=(connection, shared_key))
    t2 = threading.Thread(target=send_thread, args=(connection, shared_key))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    connection.close()

# Client mode: Connects to a server, performs handshake, and starts communication
def run_client(server_host, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))
    print(f"Connected to {server_host}:{server_port}")

    shared_key = handshake(client_socket)  # Perform handshake and generate shared key
    print("Shared key established.")

    # Start threads for receiving and sending messages
    t1 = threading.Thread(target=receive_thread, args=(client_socket, shared_key))
    t2 = threading.Thread(target=send_thread, args=(client_socket, shared_key))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    client_socket.close()

# Main function to handle command line arguments and choose between server or client mode
def main():
    parser = argparse.ArgumentParser(description="Start a client or server for secure communication.")
    parser.add_argument("mode", choices=["server", "client"], help="Run as server or client")
    parser.add_argument("--host", type=str, default=CLIENT_HOST, help="Host to connect to (for client mode)")
    parser.add_argument("--port", type=int, default=CLIENT_PORT, help="Port to connect to (for client mode)")
    args = parser.parse_args()

    if args.mode == "server":
        run_server()
    else:
        run_client(args.host, args.port)

if __name__ == "__main__":
    main()
