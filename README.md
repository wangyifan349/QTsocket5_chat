
# QTsocket5 Chat

This is a simple chat application built using **PyQt5** for the GUI and **cryptography** for secure communication. The application implements encrypted messaging between a client and a server using **X25519** for key exchange, **AES-GCM** for encryption, and **HKDF** for key derivation. This ensures that messages are exchanged securely, maintaining confidentiality and integrity.

## Features
- **Secure Messaging**: 
    - Encryption of messages using **AES-GCM** for confidentiality.
    - Key exchange using **X25519** to establish a shared key between client and server.
    - **HKDF** (HMAC-based Key Derivation Function) is used to derive the final encryption key from the shared secret.
- **Client-Server Architecture**: 
    - The client connects to a server via IP and port to send and receive encrypted messages.
    - The server listens for incoming client connections and handles the communication securely.
- **Graphical User Interface**: 
    - The application uses **PyQt5** to create a simple and user-friendly interface for chatting.
    - The client and server messages are displayed in a clean, easy-to-read format.
- **Color-Coded Messages**: 
    - Messages from the client are displayed in **gold**.
    - Messages from the server are displayed in **red**, making it easier to distinguish between the two.

## X25519 Handshake Process

The chat application uses **X25519** for secure key exchange between the client and server. Here's a simplified description of how the handshake works:

1. **Client generates key pair** → **Server generates key pair**
2. **Client sends public key** → **Server receives client's public key**
3. **Server sends its own public key** → **Client receives server's public key**
4. **Both client and server generate a shared key** → **Messages are encrypted using AES-GCM**

### Handshake Process Representation:
```

Client → \[Public Key] → Server
Server → \[Public Key] → Client
Client ↔ Server → \[Shared Key] (Derived using X25519)

````

- **Step 1**: The client and server both generate their own **X25519** key pairs.
- **Step 2**: The client sends its public key to the server.
- **Step 3**: The server sends its public key back to the client.
- **Step 4**: Both the client and server use their own private key and the received public key to derive a **shared key**.
- **Step 5**: Once the shared key is derived, both parties can securely encrypt and decrypt messages using **AES-GCM**.

This process ensures that only the client and server can decrypt the messages exchanged between them.

## Installation

To set up and run this chat application on your local machine, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/wangyifan349/QTsocket5_chat.git
    cd QTsocket5_chat
    ```

2. **Install the required dependencies**:
    Ensure you have Python installed on your system, then install the necessary dependencies using `pip`:
    ```bash
    pip install pyqt5 cryptography
    ```

3. **Run the application**:
    After installing the dependencies, you can run the application with the following command:
    ```bash
    python chat_app.py
    ```

4. **Configuration**:
    - **Client**: Choose this mode to connect to a server. Enter the server's IP address and port to initiate the connection.
    - **Server**: Choose this mode to set up a server. The server will listen for incoming client connections on the specified port.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## License Text

MIT License

Copyright (c) 2023 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

