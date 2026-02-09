import socket
def start_server():
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind to localhost and port 12345
    server_socket.bind(('localhost', 12345))
    # Start listening for client connections
    server_socket.listen(5)
    print("Server is listening on port 12345...")
    while True:
        # Accept a client connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        # Receive data from the client (in binary)
        data = client_socket.recv(1024)
        if data:
            print(f"Received data from client: {data}")
            # Send a response to the client in binary (Hello World in binary)
            response = b'Hello World'  # Response in binary format
            client_socket.sendall(response)
        # Close the connection with the client
        client_socket.close()
start_server()





import socket
def start_client():
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the server at localhost:12345
    client_socket.connect(('localhost', 12345))
    # Send some binary data to the server
    message = b'Client says Hello'  # Message in binary format
    client_socket.sendall(message)
    # Receive the server's response (in binary)
    response = client_socket.recv(1024)
    print(f"Server response: {response}")
    # Close the connection
    client_socket.close()
start_client()
