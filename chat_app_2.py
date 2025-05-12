import sys
import socket
import os
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QRadioButton,
    QGridLayout,
    QMessageBox,
    QButtonGroup
)
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtGui import QFont
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import ChaCha20_Poly1305  # PyCryptodome
# -------- Chat Thread Class --------
class ChatThread(QThread):
    message_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    def __init__(self, connection, shared_key):
        super().__init__()
        self.connection = connection
        self.shared_key = shared_key[:32]  # ChaCha20 requires a 32-byte key
        self.running = True
    def run(self):
        while self.running:
            try:
                # Receive nonce, tag, and ciphertext
                nonce = self.connection.recv(12)  # Crucial nonce for ChaCha20
                tag = self.connection.recv(16)    # Authentication tag for integrity
                ciphertext = self.connection.recv(1024)  # The encrypted message
                if not ciphertext:
                    break 
                # Decrypt and verify
                plaintext_bytes = self.decrypt_message(nonce, tag, ciphertext)
                plaintext = plaintext_bytes.decode()
                self.message_received.emit(f"[Other]: {plaintext}")  # Emit the plaintext message
            except Exception as e:
                self.error_occurred.emit(f"Receive error: {e}")  # Emit error if any occurs
    def stop(self):
        self.running = False
        if self.connection:
            self.connection.close()  # Close socket connection on stop

    def decrypt_message(self, nonce, tag, ciphertext):
        """Decrypt message using ChaCha20-Poly1305, verify with tag."""
        cipher = ChaCha20_Poly1305.new(key=self.shared_key, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify integrity

# -------- Chat Application Class --------
class ChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shared_key = None
        self.connection = None
        self.thread = None

    def initUI(self):
        # Window setup
        self.setWindowTitle('Secure Chat')
        self.setGeometry(100, 100, 800, 600)  # Increased window size

        # Font settings
        font = QFont('Courier', 12)  # Set font to Courier with size 12
        self.setFont(font)
        # Create a tab widget for configuration and chat
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        # Configuration tab setup
        self.configTab = QWidget()
        self.configLayout = QGridLayout()
        self.configTab.setLayout(self.configLayout)
        # Configuration UI elements
        self.modeLabel = QLabel("Mode:")
        self.clientRadio = QRadioButton("Client")
        self.serverRadio = QRadioButton("Server")
        self.modeGroup = QButtonGroup(self)
        self.modeGroup.addButton(self.clientRadio)
        self.modeGroup.addButton(self.serverRadio)

        self.ipInput = QLineEdit()
        self.portInput = QLineEdit()
        self.ipInput.setPlaceholderText("Enter IP address")
        self.portInput.setPlaceholderText("Enter Port")

        self.startButton = QPushButton("Start")

        # Add configuration UI elements to layout
        self.configLayout.addWidget(self.modeLabel, 0, 0)
        self.configLayout.addWidget(self.clientRadio, 1, 0)
        self.configLayout.addWidget(self.serverRadio, 1, 1)
        self.configLayout.addWidget(QLabel("IP Address:"), 2, 0)
        self.configLayout.addWidget(self.ipInput, 2, 1)
        self.configLayout.addWidget(QLabel("Port:"), 3, 0)
        self.configLayout.addWidget(self.portInput, 3, 1)
        self.configLayout.addWidget(self.startButton, 4, 0, 1, 2)
        # Chat tab setup
        self.chatTab = QWidget()
        self.chatLayout = QVBoxLayout()
        self.chatTab.setLayout(self.chatLayout)
        # Chat UI elements
        self.chatDisplay = QTextEdit()
        self.chatDisplay.setReadOnly(True)
        self.chatDisplay.setStyleSheet("font: 12pt 'Courier';")
        self.messageInput = QLineEdit()
        self.sendButton = QPushButton("Send")
        # Add chat UI elements to layout
        self.chatLayout.addWidget(self.chatDisplay)
        self.chatLayout.addWidget(self.messageInput)
        self.chatLayout.addWidget(self.sendButton)
        # Add tabs to the widget
        self.tabs.addTab(self.configTab, "Configuration")
        self.tabs.addTab(self.chatTab, "Chat")
        # Connect buttons to functions
        self.startButton.clicked.connect(self.start_connection)
        self.sendButton.clicked.connect(self.send_message)
    # -------- Encryption Methods --------
    def create_shared_key(self, private_key, peer_public_bytes):
        """Generate a shared key using X25519."""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_key = private_key.exchange(peer_public_key)
        return shared_key
    def derive_key(self, shared_key):
        """Derive a final key using HKDF."""
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)  # HKDF used for key derivation
        return derived_key
    def encrypt_message(self, key, plaintext):
        """Encrypt message using ChaCha20-Poly1305."""
        cipher = ChaCha20_Poly1305.new(key=key)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce, tag, ciphertext  # Return nonce, tag, and ciphertext
    # -------- Messaging Methods --------
    def send_message(self):
        """Send a message to the peer."""
        try:
            message = self.messageInput.text().encode()
            if message and self.shared_key:
                nonce, tag, ciphertext = self.encrypt_message(self.shared_key[:32], message)
                self.connection.sendall(nonce)       # Send the nonce
                self.connection.sendall(tag)         # Send the tag for integrity check
                self.connection.sendall(ciphertext)  # Send the ciphertext
                self.chatDisplay.append(f'<font color="gold">Sent: {message.decode()}</font>')  # Display sent message
                self.messageInput.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Send error: {e}")  # Error handling

    # -------- Connection Setup Methods --------
    def start_connection(self):
        """Start the connection based on the selected mode."""
        host = self.ipInput.text().strip()
        try:
            port = int(self.portInput.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Please enter a valid port number.")
            return

        if self.clientRadio.isChecked():  # Check if client mode is selected
            self.start_client(host, port)
        elif self.serverRadio.isChecked():  # Check if server mode is selected
            self.start_server(port)

    def start_client(self, host, port):
        """Start client and connect to the server."""
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((host, port))  # Connect to the server

            # Generate key pair for X25519
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Serialize the public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            # Send public key and receive peer's public key
            self.connection.sendall(public_key_bytes)
            peer_public_bytes = self.connection.recv(32)
            # Create and derive shared key
            shared_key = self.create_shared_key(private_key, peer_public_bytes)
            self.shared_key = self.derive_key(shared_key)
            # Complete handshake
            self.connection.sendall(b'handshake complete')
            # Setup chat window
            self.chatDisplay.append("Connected to server.")
            self.tabs.setCurrentIndex(1)
            # Start receiving thread
            self.thread = ChatThread(self.connection, self.shared_key)
            self.thread.message_received.connect(self.chatDisplay.append)  # Connect message received signal
            self.thread.error_occurred.connect(self.show_error)  # Connect error occurred signal
            self.thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not start client: {e}")  # Error handling
    def start_server(self, port):
        """Start server and wait for client connection."""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(('0.0.0.0', port))  # Listen on all available interfaces
            server_sock.listen()
            # Wait for client connection
            self.connection, addr = server_sock.accept()
            self.chatDisplay.append(f"Client connected: {addr}")
            # Receive client's public key and send own public key
            peer_public_bytes = self.connection.recv(32)
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            # Serialize the public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self.connection.sendall(public_key_bytes)
            # Create and derive shared key
            shared_key = self.create_shared_key(private_key, peer_public_bytes)
            self.shared_key = self.derive_key(shared_key)
            # Complete handshake
            handshake_msg = self.connection.recv(1024)
            if handshake_msg == b'handshake complete':
                self.chatDisplay.append("Client handshake complete.")
                self.tabs.setCurrentIndex(1)
                # Start receiving thread
                self.thread = ChatThread(self.connection, self.shared_key)
                self.thread.message_received.connect(self.chatDisplay.append)  # Connect message received signal
                self.thread.error_occurred.connect(self.show_error)  # Connect error occurred signal
                self.thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Server setup error: {e}")  # Error handling
    # -------- Error Handling Method --------
    def show_error(self, message):
        """Show error messages."""
        QMessageBox.warning(self, "Error", message)  # Display warning message
# -------- Main Execution --------
if __name__ == '__main__':
    app = QApplication(sys.argv)
    chatApp = ChatApp()  # Initialize ChatApp
    chatApp.show()       # Display the main window
    sys.exit(app.exec_())  # Start the application's event loop
