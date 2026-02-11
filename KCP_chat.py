import socket
import threading
import sys
import base64
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

"""
This program implements a secure chat application where the client and server exchange public keys using the X25519 key exchange protocol. 
After exchanging keys, they use the AES encryption algorithm to encrypt the communication. The communication is done over UDP, and KCP (a reliable transport protocol) ensures the messages are delivered reliably.
The main process involves:
1. The client and server exchange public keys using X25519 and generate a shared secret key.
2. The client and server then use this shared key to generate an AES key for encrypting and decrypting messages.
3. The KCP protocol ensures the reliable transmission of messages between the client and server.
4. The client and server have separate threads for receiving and sending messages.
Communication Protocol:
- The communication between the client and server uses UDP as the base transport protocol, with KCP ensuring reliability.
- Messages between the client and server are encrypted using AES to ensure confidentiality.
"""
# AES encryption
def encrypt(data, key):  # Encrypt data using AES
    cipher = AES.new(key, AES.MODE_CBC)  # CBC mode
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))  # Encrypt the data
    iv = base64.b64encode(cipher.iv).decode('utf-8')  # Encode the IV
    ct = base64.b64encode(ct_bytes).decode('utf-8')  # Encode the ciphertext
    return iv + ct  # Return IV + ciphertext
# AES decryption
def decrypt(data, key):  # Decrypt data using AES
    iv = base64.b64decode(data[:24])  # Extract the IV
    ct = base64.b64decode(data[24:])  # Extract the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Use the same AES key to decrypt
    pt = unpad(cipher.decrypt(ct), AES.block_size)  # Decrypt and unpad
    return pt.decode()  # Return the decrypted data

# Generate shared secret key using X25519
def generate_shared_key(private_key, remote_public_key):  # Generate shared secret using X25519
    private_key = PrivateKey(private_key)  # Convert private key to PrivateKey instance
    remote_public_key = PublicKey(remote_public_key)  # Convert remote public key to PublicKey instance
    box = Box(private_key, remote_public_key)  # Create a Box instance for encryption
    shared_key = box.shared_key()  # Generate the shared secret key
    return shared_key  # Return the shared secret key

# Server to receive and send messages
def handle_client(server_socket, kcp_server, shared_key):
    while True:
        data, addr = server_socket.recvfrom(1024)  # Receive data from the client
        decrypted_data = decrypt(data.decode(), shared_key)  # Decrypt the received data
        print(f"Received from {addr[0]}:{addr[1]} - {decrypted_data}")  # Print the sender's IP and the message content
        response = input("Server (Reply): ")  # Get the response from the server
        encrypted_response = encrypt(response, shared_key)  # Encrypt the response
        kcp_server.send(encrypted_response.encode())  # Send the encrypted response via KCP
        server_socket.sendto(encrypted_response.encode(), addr)  # Send the encrypted response to the client

# Server logic
def kcp_server(private_key):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
    server_socket.bind(('localhost', 12345))  # Bind to the local port
    kcp_server = kcp.KCP(0x11223344, server_socket)  # Initialize KCP server
    print("KCP Server started on port 12345...")
    server_private_key = PrivateKey.generate()  # Generate server's private key
    server_public_key = server_private_key.public_key  # Get server's public key
    print(f"Server's public key: {server_public_key.encode(encoder=Base64Encoder).decode()}")
    client_public_key = input("Enter the client's public key: ")  # Get the client's public key
    client_public_key = base64.b64decode(client_public_key)  # Decode the public key
    shared_key = generate_shared_key(server_private_key.encode(), client_public_key)  # Generate shared key using private key and client's public key
    threading.Thread(target=handle_client, args=(server_socket, kcp_server, shared_key), daemon=True).start()  # Start receiving thread
    while True:
        kcp_server.update()  # Update KCP protocol
        response = input("Server (Reply): ")  # Get message to send
        encrypted_response = encrypt(response, shared_key)  # Encrypt the message
        kcp_server.send(encrypted_response.encode())  # Send the encrypted message
        server_socket.sendto(encrypted_response.encode(), ('localhost', 12345))  # Send to the client

# Client to receive messages and print them
def receive_messages(client_socket, kcp_client, shared_key):
    while True:
        data, addr = client_socket.recvfrom(1024)  # Receive data
        decrypted_data = decrypt(data.decode(), shared_key)  # Decrypt data
        print(f"Received: {decrypted_data} from {addr}")

# Client to send messages
def send_messages(client_socket, kcp_client, server_ip, shared_key):
    while True:
        message = input("Client (Send): ")  # Get the message to send
        encrypted_message = encrypt(message, shared_key)  # Encrypt the message
        kcp_client.send(encrypted_message.encode())  # Send encrypted message via KCP
        client_socket.sendto(encrypted_message.encode(), (server_ip, 12345))  # Send to server

# Client logic
def kcp_client(server_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
    kcp_client = kcp.KCP(0x11223344, client_socket)  # Initialize KCP client
    client_private_key = PrivateKey.generate()  # Generate client private key
    client_public_key = client_private_key.public_key  # Get client public key
    print(f"Client's public key: {client_public_key.encode(encoder=Base64Encoder).decode()}")
    server_public_key = input("Enter the server's public key: ")  # Get the server's public key
    server_public_key = base64.b64decode(server_public_key)  # Decode server's public key
    shared_key = generate_shared_key(client_private_key.encode(), server_public_key)  # Generate shared key using private key and server's public key
    threading.Thread(target=receive_messages, args=(client_socket, kcp_client, shared_key), daemon=True).start()  # Start receiving thread
    while True:
        send_messages(client_socket, kcp_client, server_ip, shared_key)  # Send messages

# Main function to choose between server or client
def main():
    if len(sys.argv) < 2:  # Check command-line arguments
        print("Usage: python chat.py [server|client] [server_ip(optional)]")
        sys.exit(1)
    if sys.argv[1] == "server":  # Run as server
        kcp_server(None)
    elif sys.argv[1] == "client":  # Run as client
        if len(sys.argv) < 3:
            print("For client mode, you need to specify the server IP address.")
            sys.exit(1)
        server_ip = sys.argv[2]
        kcp_client(server_ip)
    else:
        print("Invalid argument. Use 'server' or 'client'.")
        sys.exit(1)

if __name__ == "__main__":
    main()  # Start the program
