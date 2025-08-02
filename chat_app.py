import sys
import socket
import os
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QHBoxLayout,
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


class ChatThread(QThread):
    message_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, connection, shared_key):
        super().__init__()
        self.connection = connection
        self.shared_key = shared_key

    def run(self):
        while True:
            try:
                data = self.connection.recv(1024)
                if not data:
                    break

                nonce, ciphertext = data[:12], data[12:]
                aesgcm = AESGCM(self.shared_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()

                self.message_received.emit(f'<font color="green">Received: {plaintext}</font>')

            except Exception as e:
                self.error_occurred.emit(f"Error receiving message: {e}")
                break


class ChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.shared_key = None
        self.connection = None
        self.thread = None

    def initUI(self):
        self.setWindowTitle('Secure Chat')
        self.setGeometry(100, 100, 800, 600)

        font = QFont('Courier', 12)
        self.setFont(font)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.configTab = QWidget()
        self.configLayout = QGridLayout()
        self.configTab.setLayout(self.configLayout)

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

        self.configLayout.addWidget(self.modeLabel, 0, 0)
        self.configLayout.addWidget(self.clientRadio, 1, 0)
        self.configLayout.addWidget(self.serverRadio, 1, 1)
        self.configLayout.addWidget(QLabel("IP Address:"), 2, 0)
        self.configLayout.addWidget(self.ipInput, 2, 1)
        self.configLayout.addWidget(QLabel("Port:"), 3, 0)
        self.configLayout.addWidget(self.portInput, 3, 1)
        self.configLayout.addWidget(self.startButton, 4, 0, 1, 2)

        self.chatTab = QWidget()
        self.chatLayout = QVBoxLayout()
        self.chatTab.setLayout(self.chatLayout)

        self.chatDisplay = QTextEdit()
        self.chatDisplay.setReadOnly(True)
        self.chatDisplay.setStyleSheet("font: 12pt 'Courier';")

        self.messageInput = QLineEdit()
        self.sendButton = QPushButton("Send")

        self.chatLayout.addWidget(self.chatDisplay)
        self.chatLayout.addWidget(self.messageInput)
        self.chatLayout.addWidget(self.sendButton)

        self.tabs.addTab(self.configTab, "Configuration")
        self.tabs.addTab(self.chatTab, "Chat")

        self.startButton.clicked.connect(self.start_connection)
        self.sendButton.clicked.connect(self.send_message)

    def create_shared_key(self, private_key, peer_public_bytes):
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_key = private_key.exchange(peer_public_key)
        return shared_key

    def derive_key(self, shared_key):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key

    def encrypt_message(self, key, plaintext):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def send_message(self):
        try:
            message = self.messageInput.text().encode()
            if message and self.shared_key:
                ciphertext = self.encrypt_message(self.shared_key, message)
                self.connection.sendall(ciphertext)
                self.chatDisplay.append(f'<font color="gold">Sent: {message.decode()}</font>')
                self.messageInput.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Send error: {e}")

    def start_connection(self):
        host = self.ipInput.text().strip()
        try:
            port = int(self.portInput.text().strip())
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Please enter a valid port number.")
            return

        if self.clientRadio.isChecked():
            self.start_client(host, port)
        elif self.serverRadio.isChecked():
            self.start_server(port)
        else:
            QMessageBox.warning(self, "Input Error", "Please select Client or Server mode.")

    def start_client(self, host, port):
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((host, port))

            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            self.connection.sendall(public_key_bytes)
            peer_public_bytes = self.connection.recv(32)

            shared_key = self.create_shared_key(private_key, peer_public_bytes)
            self.shared_key = self.derive_key(shared_key)

            self.connection.sendall(b'handshake complete')

            self.chatDisplay.append("Connected to server.")
            self.tabs.setCurrentIndex(1)

            self.thread = ChatThread(self.connection, self.shared_key)
            self.thread.message_received.connect(self.chatDisplay.append)
            self.thread.error_occurred.connect(self.show_error)
            self.thread.start()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not start client: {e}")

    def start_server(self, port):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(('0.0.0.0', port))
            server_sock.listen()

            self.chatDisplay.append("Waiting for client to connect...")
            self.connection, addr = server_sock.accept()
            self.chatDisplay.append(f"Client connected: {addr}")

            peer_public_bytes = self.connection.recv(32)
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self.connection.sendall(public_key_bytes)

            shared_key = self.create_shared_key(private_key, peer_public_bytes)
            self.shared_key = self.derive_key(shared_key)

            handshake_msg = self.connection.recv(1024)
            if handshake_msg == b'handshake complete':
                self.chatDisplay.append("Client handshake complete.")
                self.tabs.setCurrentIndex(1)

                self.thread = ChatThread(self.connection, self.shared_key)
                self.thread.message_received.connect(self.chatDisplay.append)
                self.thread.error_occurred.connect(self.show_error)
                self.thread.start()
            else:
                raise Exception("Handshake failed or invalid handshake message")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not start server: {e}")

    def show_error(self, error_msg):
        QMessageBox.warning(self, "Connection Error", error_msg)

    def closeEvent(self, event):
        try:
            if self.connection:
                self.connection.close()
        except Exception:
            pass
        event.accept()


def main():
    app = QApplication(sys.argv)
    chat_app = ChatApp()
    chat_app.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
