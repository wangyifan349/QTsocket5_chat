#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
*This program demonstrates a secure chat and file transfer system using PyQt5, X25519 for key exchange, 
and ChaCha20Poly1305 for AEAD encryption. It sets up a graphical interface that allows one to act as either 
server or client, then negotiates an ephemeral shared secret and encrypts all transmissions.*

*The ciphertext structure is: [4-byte encrypted-length][12-byte nonce + ciphertext], where the first 4 bytes 
indicate how many bytes of nonce+ciphertext follow. The ChaCha20-Poly1305 cipher includes an authentication 
tag that verifies the integrity of the data. Additionally, for file transfers, each file is split into chunks 
of data, and the final chunk carries a SHA-256 checksum to ensure end-to-end data correctness.*

*Internally, X25519 is leveraged to derive a shared key. HKDF-SHA256 expands this shared secret into a 32-byte 
session key. Each message uses a unique nonce, composed of a 4-byte random prefix and an 8-byte counter. If 
a malicious entity tampers with a packet, decryption fails immediately. The entire UI remains responsive 
because sending and receiving operate in a separate thread.*
"""

import sys
import os
import socket
import struct
import hashlib
import threading
import pathlib

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
    QPushButton, QTextEdit, QFileDialog, QVBoxLayout, QHBoxLayout,
    QRadioButton, QGroupBox, QButtonGroup
)
from PyQt5.QtGui import QPalette, QColor

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Constants for message types and frame sizes.  ←
MessageTypeText = b'M'
MessageTypeFileHead = b'H'
MessageTypeFileChunk = b'C'
MessageTypeFileEnd = b'E'

FrameLengthSize = 4           # 4-byte length header for each encrypted frame.  ←
NonceLength = 12              # 4-byte random prefix + 8-byte counter.  ←
FileChunkSize = 32 * 1024     # Send file in 32 KB chunks.  ←

class NetworkThread(QThread):
    """
    NetworkThread class handles all socket operations:
    1) Server or client setup (TCP).
    2) X25519 ephemeral key exchange + HKDF to get ChaCha20Poly1305 key.
    3) Encrypting and decrypting data frames.
    4) Handling both chat messages and file transmissions in a background thread.
    """

    signalLog = pyqtSignal(str)                        # Signal for logging text to UI.  ←
    signalConnected = pyqtSignal(bool)                 # Signal to indicate successful or failed connection.  ←
    signalMessage = pyqtSignal(str)                    # Signal for plain text messages.  ←
    signalFileStart = pyqtSignal(str, int, str)        # Signal when file transfer starts: filename, size, save path.  ←
    signalFileProgress = pyqtSignal(str, int, int)     # Signal to update file progress: filename, received, total.  ←
    signalFileFinish = pyqtSignal(str, bool, str)      # Signal when file ends: filename, success, path.  ←

    def __init__(self, startupMode, hostAddress, portNumber, parent=None):
        super().__init__(parent)
        self.startupMode = startupMode
        self.hostAddress = hostAddress
        self.portNumber = portNumber
        self.networkSocket = None
        self.threadRunning = True
        self.aeadCipher = None
        self.noncePrefixBytes = None
        self.nonceCounter = 0
        self.incomingFilesMap = {}  # Dictionary mapping filename => { fileobj, remain, sha256Digest, path, size, received }

    def run(self):
        """
        The main logic executed by QThread. Sets up server or client, handles key exchange, 
        then loops receiving packets until disconnection or error.  ←
        """
        try:
            if self.startupMode == "server":
                serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                serverSocket.bind((self.hostAddress, self.portNumber))
                serverSocket.listen(1)
                self.signalLog.emit(f"[Server] Listening at {self.hostAddress}:{self.portNumber} ...")
                connection, addressInfo = serverSocket.accept()
                self.networkSocket = connection
                self.signalLog.emit(f"[Server] Connected from {addressInfo}")
            else:
                self.signalLog.emit(f"[Client] Connecting to {self.hostAddress}:{self.portNumber} ...")
                clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clientSocket.connect((self.hostAddress, self.portNumber))
                self.networkSocket = clientSocket
                self.signalLog.emit("[Client] Connection established")

            self.performKeyExchange()

            self.signalConnected.emit(True)

            while self.threadRunning:
                frameData = self.receiveFrame()
                if not frameData:
                    break
                self.processReceivedMessage(frameData)

        except Exception as exceptionInfo:
            self.signalLog.emit("[!] Connection or thread error: " + str(exceptionInfo))
            self.signalConnected.emit(False)
        finally:
            if self.networkSocket:
                self.networkSocket.close()
            self.threadRunning = False

    def performKeyExchange(self):
        """
        Performs ephemeral X25519 key exchange:
        1) Generate ephemeral private key.
        2) If in server mode, send pubKey first, then receive. Else, receive first, then send.
        3) Derive a 32-byte session key by HKDF(SHA256).
        4) Initialize ChaCha20Poly1305 with that session key.
        """
        privateKey = X25519PrivateKey.generate()
        localPubBytes = privateKey.public_key().public_bytes()

        if self.startupMode == "server":
            self.sendAll(localPubBytes)                  # send first
            remotePub = self.receiveExact(32)            # then receive
        else:
            remotePub = self.receiveExact(32)            # receive first
            self.sendAll(localPubBytes)                  # then send

        remoteKey = X25519PublicKey.from_public_bytes(remotePub)
        sharedSecret = privateKey.exchange(remoteKey)

        # KDF step
        hkdfProcessor = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"secure-chat-pyqt"
        )
        sessionKey = hkdfProcessor.derive(sharedSecret)

        self.aeadCipher = ChaCha20Poly1305(sessionKey)
        self.noncePrefixBytes = os.urandom(4)
        self.nonceCounter = 0

        self.signalLog.emit("[+] Secure channel established (X25519 + ChaCha20Poly1305)")

    def buildNonce(self) -> bytes:
        """
        Builds a unique nonce = 4-byte random prefix + 8-byte big-endian counter.
        """
        counterBytes = struct.pack(">Q", self.nonceCounter)
        self.nonceCounter = (self.nonceCounter + 1) & 0xFFFFFFFFFFFFFFFF
        return self.noncePrefixBytes + counterBytes

    def encryptData(self, plaintext: bytes) -> bytes:
        """
        Encrypts data with ChaCha20Poly1305. Returns 12-byte nonce + ciphertext.  ←
        """
        nonceBytes = self.buildNonce()
        cipherText = self.aeadCipher.encrypt(nonceBytes, plaintext, None)
        return nonceBytes + cipherText

    def decryptData(self, encryptedData: bytes) -> bytes:
        """
        Decrypts data by splitting out the 12-byte nonce from the ciphertext.  ←
        """
        nonceBytes = encryptedData[:NonceLength]
        cipherBody = encryptedData[NonceLength:]
        return self.aeadCipher.decrypt(nonceBytes, cipherBody, None)

    def sendFrame(self, plaintext: bytes):
        """
        Encrypts and sends a frame: [4-byte length][12-byte nonce + ciphertext].  ←
        """
        enc = self.encryptData(plaintext)
        header = struct.pack(">I", len(enc))
        self.sendAll(header + enc)

    def receiveFrame(self) -> bytes:
        """
        Receives an encrypted frame, then decrypts it. Returns plaintext.  ←
        """
        lengthHeader = self.receiveExact(FrameLengthSize)
        if not lengthHeader:
            return b''
        totalLen = struct.unpack(">I", lengthHeader)[0]
        encryptedFrame = self.receiveExact(totalLen)
        return self.decryptData(encryptedFrame)

    def sendAll(self, data: bytes):
        """
        Sends all data over the socket until complete.  ←
        """
        if self.networkSocket:
            self.networkSocket.sendall(data)

    def receiveExact(self, size: int) -> bytes:
        """
        Receives 'size' bytes exactly from the socket, 
        or raises ConnectionError if the peer closes.  ←
        """
        bufferData = b''
        while len(bufferData) < size:
            chunk = self.networkSocket.recv(size - len(bufferData))
            if not chunk:
                raise ConnectionError("Remote side closed the connection.")
            bufferData += chunk
        return bufferData

    def processReceivedMessage(self, messageData: bytes):
        """
        Distinguishes the message type and handles accordingly.
        For file, it uses a dictionary to store partial data and finalize at the end.  ←
        """
        messageType = messageData[:1]
        bodyData = messageData[1:]

        if messageType == MessageTypeText:
            textString = bodyData.decode('utf-8', errors='ignore')
            self.signalMessage.emit(textString)

        elif messageType == MessageTypeFileHead:
            fileNameLength = struct.unpack(">H", bodyData[:2])[0]
            fileNameString = bodyData[2:2 + fileNameLength].decode('utf-8', errors='ignore')
            fileSize = struct.unpack(">Q", bodyData[2 + fileNameLength:2 + fileNameLength + 8])[0]

            baseFileName = pathlib.Path(fileNameString).name
            targetPath = pathlib.Path(baseFileName)
            indexCount = 1
            while targetPath.exists():
                targetPath = pathlib.Path(f"{baseFileName}_{indexCount}")
                indexCount += 1

            openedFile = targetPath.open("wb")
            self.incomingFilesMap[fileNameString] = {
                "fileObject": openedFile,
                "remainBytes": fileSize,
                "sha256Digest": hashlib.sha256(),
                "filePath": str(targetPath),
                "sizeBytes": fileSize,
                "receivedBytes": 0
            }
            self.signalFileStart.emit(fileNameString, fileSize, str(targetPath))

        elif messageType == MessageTypeFileChunk:
            fileNameLength = struct.unpack(">H", bodyData[:2])[0]
            fileNameString = bodyData[2:2 + fileNameLength].decode('utf-8', errors='ignore')
            chunkData = bodyData[2 + fileNameLength:]
            if fileNameString in self.incomingFilesMap:
                infoDict = self.incomingFilesMap[fileNameString]
                fobj = infoDict["fileObject"]
                fobj.write(chunkData)
                infoDict["sha256Digest"].update(chunkData)
                infoDict["remainBytes"] -= len(chunkData)
                infoDict["receivedBytes"] += len(chunkData)
                self.signalFileProgress.emit(fileNameString, infoDict["receivedBytes"], infoDict["sizeBytes"])

        elif messageType == MessageTypeFileEnd:
            fileNameLength = struct.unpack(">H", bodyData[:2])[0]
            fileNameString = bodyData[2:2 + fileNameLength].decode('utf-8', errors='ignore')
            fileDigest = bodyData[2 + fileNameLength:]
            if fileNameString in self.incomingFilesMap:
                infoDict = self.incomingFilesMap.pop(fileNameString)
                fobj = infoDict["fileObject"]
                fobj.close()
                realDigest = infoDict["sha256Digest"].digest()
                successCheck = (fileDigest == realDigest)
                self.signalFileFinish.emit(fileNameString, successCheck, infoDict["filePath"])

    def sendText(self, textContent: str):
        """
        Public method to send a text message to the peer.  ←
        """
        if not self.aeadCipher:
            return
        plainMessage = MessageTypeText + textContent.encode('utf-8')
        self.sendFrame(plainMessage)

    def sendFile(self, filePathName: str):
        """
        Public method to send a file in chunks, plus a final SHA-256.  ←
        """
        pathObject = pathlib.Path(filePathName)
        if not pathObject.is_file():
            self.signalLog.emit(f"[!] File not found: {filePathName}")
            return

        fileNameBytes = pathObject.name.encode('utf-8')
        fileSize = pathObject.stat().st_size

        # Step 1: Send File Head
        headMessage = (MessageTypeFileHead +
                       struct.pack(">H", len(fileNameBytes)) +
                       fileNameBytes +
                       struct.pack(">Q", fileSize))
        self.sendFrame(headMessage)

        # Step 2: Send File Chunks and do SHA-256
        localSha256 = hashlib.sha256()
        with pathObject.open("rb") as readingFile:
            while True:
                chunk = readingFile.read(FileChunkSize)
                if not chunk:
                    break
                localSha256.update(chunk)
                chunkMessage = (MessageTypeFileChunk +
                                struct.pack(">H", len(fileNameBytes)) +
                                fileNameBytes +
                                chunk)
                self.sendFrame(chunkMessage)

        # Step 3: Send File End (with final digest)
        digestResult = localSha256.digest()
        endMessage = (MessageTypeFileEnd +
                      struct.pack(">H", len(fileNameBytes)) +
                      fileNameBytes +
                      digestResult)
        self.sendFrame(endMessage)
        self.signalLog.emit(f"File sent: {filePathName} ({fileSize} bytes)")

class MainWindow(QMainWindow):
    """
    MainWindow provides the PyQt5 UI:
    - Radio buttons to select server or client.
    - Fields for host address, port.
    - Chat log display, text input, and file sending button.
    - Uses a background NetworkThread for all TCP + ECDH + encryption tasks.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat (X25519 + ChaCha20Poly1305)")
        self.resize(800, 600)

        # Set color theme using QPalette.  ←
        mainPalette = QPalette()
        mainPalette.setColor(QPalette.Window, QColor("#FFF8DC"))   # cornsilk
        mainPalette.setColor(QPalette.Base, QColor("#F5FFFA"))     # mintcream
        mainPalette.setColor(QPalette.AlternateBase, QColor("#FFFFE0"))
        self.setPalette(mainPalette)

        # Mode selection group
        self.radioServerMode = QRadioButton("Server Mode")
        self.radioClientMode = QRadioButton("Client Mode")
        self.radioServerMode.setChecked(True)
        self.buttonGroupMode = QButtonGroup()
        self.buttonGroupMode.addButton(self.radioServerMode)
        self.buttonGroupMode.addButton(self.radioClientMode)

        self.hostAddressLineEdit = QLineEdit("127.0.0.1")
        self.portNumberLineEdit = QLineEdit("9999")
        self.startConnectionButton = QPushButton("Start or Connect")

        modeLayout = QHBoxLayout()
        modeLayout.addWidget(self.radioServerMode)
        modeLayout.addWidget(self.radioClientMode)
        modeLayout.addWidget(QLabel("Host:"))
        modeLayout.addWidget(self.hostAddressLineEdit)
        modeLayout.addWidget(QLabel("Port:"))
        modeLayout.addWidget(self.portNumberLineEdit)
        modeLayout.addWidget(self.startConnectionButton)

        modeGroupBox = QGroupBox("Startup Mode")
        modeGroupBox.setLayout(modeLayout)

        # Chat log and controls
        self.chatLogTextEdit = QTextEdit()
        self.chatLogTextEdit.setReadOnly(True)

        self.messageLineEdit = QLineEdit()
        self.sendMessageButton = QPushButton("Send Message")
        self.sendFileButton = QPushButton("Send File")

        bottomLayout = QHBoxLayout()
        bottomLayout.addWidget(self.messageLineEdit)
        bottomLayout.addWidget(self.sendMessageButton)
        bottomLayout.addWidget(self.sendFileButton)

        mainLayout = QVBoxLayout()
        mainLayout.addWidget(modeGroupBox)
        mainLayout.addWidget(self.chatLogTextEdit)
        mainLayout.addLayout(bottomLayout)

        containerWidget = QWidget()
        containerWidget.setLayout(mainLayout)
        self.setCentralWidget(containerWidget)

        # Thread reference
        self.networkThread = None

        # Signals
        self.startConnectionButton.clicked.connect(self.handleConnectClicked)
        self.sendMessageButton.clicked.connect(self.handleSendClicked)
        self.sendFileButton.clicked.connect(self.handleFileClicked)

    def handleConnectClicked(self):
        """
        Called when Start/Connect button is pressed. Sets up and starts the background thread.  ←
        """
        if self.networkThread and self.networkThread.isRunning():
            self.chatLogTextEdit.append("Already running or connected.")
            return

        currentMode = "server" if self.radioServerMode.isChecked() else "client"
        hostStr = self.hostAddressLineEdit.text().strip()
        portVal = int(self.portNumberLineEdit.text().strip())

        self.networkThread = NetworkThread(currentMode, hostStr, portVal)
        self.networkThread.signalLog.connect(self.logAppend)
        self.networkThread.signalConnected.connect(self.handleConnected)
        self.networkThread.signalMessage.connect(self.handlePeerMessage)
        self.networkThread.signalFileStart.connect(self.handleFileStart)
        self.networkThread.signalFileProgress.connect(self.handleFileProgress)
        self.networkThread.signalFileFinish.connect(self.handleFileFinish)
        self.networkThread.start()

    def logAppend(self, text: str):
        """
        Appends a line of text to the chat log.  ←
        """
        self.chatLogTextEdit.append(text)

    def handleConnected(self, ok: bool):
        """
        Called when the thread reports a successful or failed connection.  ←
        """
        if ok:
            self.chatLogTextEdit.append("===== Secure connection established =====")
        else:
            self.chatLogTextEdit.append("### Connection failed or closed ###")

    def handlePeerMessage(self, text: str):
        """
        Called when a text message from peer arrives.  ←
        """
        self.chatLogTextEdit.append(f"<Peer>: {text}")

    def handleFileStart(self, fileName: str, fileSize: int, savePath: str):
        """
        Called when an incoming file is about to be received.  ←
        """
        self.chatLogTextEdit.append(f"Receiving file: {fileName} ({fileSize} bytes) -> {savePath}")

    def handleFileProgress(self, fileName: str, receivedBytes: int, totalBytes: int):
        """
        Called as chunks of file data arrive.  ←
        """
        pct = float(receivedBytes) / float(totalBytes) * 100 if totalBytes else 0
        self.chatLogTextEdit.append(f"[FileProgress] {fileName}: {receivedBytes}/{totalBytes} ({pct:.1f}%)")

    def handleFileFinish(self, fileName: str, successCheck: bool, pathUsed: str):
        """
        Called when the file transfer completes, verifying SHA-256.  ←
        """
        if successCheck:
            self.chatLogTextEdit.append(f"File received OK: {fileName} -> {pathUsed}")
        else:
            self.chatLogTextEdit.append(f"File corrupted: {fileName} -> {pathUsed}")

    def handleSendClicked(self):
        """
        Sends a chat message to the peer if connected.  ←
        """
        if not self.networkThread or not self.networkThread.isRunning():
            self.chatLogTextEdit.append("Not connected, cannot send.")
            return
        textToSend = self.messageLineEdit.text().strip()
        if textToSend:
            self.networkThread.sendText(textToSend)
            self.chatLogTextEdit.append(f"<Me>: {textToSend}")
            self.messageLineEdit.clear()

    def handleFileClicked(self):
        """
        Opens a file dialog and, if chosen, sends the selected file.  ←
        """
        if not self.networkThread or not self.networkThread.isRunning():
            self.chatLogTextEdit.append("Not connected, cannot send file.")
            return
        fileName, _ = QFileDialog.getOpenFileName(self, "Select File")
        if fileName:
            self.chatLogTextEdit.append(f"Sending file: {fileName}")
            self.networkThread.sendFile(fileName)

def MainEntryPoint():
    """
    Main entry point for launching the PyQt application.  ←
    """
    applicationObject = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(applicationObject.exec_())

if __name__ == "__main__":
    MainEntryPoint()



"""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This script demonstrates a secure terminal-based chat and file transfer tool using:
1) X25519 for ephemeral key exchange (each side generates a temporary private key).
2) HKDF-SHA256 to derive a 32-byte session key from the shared secret.
3) ChaCha20Poly1305 (AEAD) with unique nonces to encrypt all messages.
4) Threaded send/receive to prevent blocking, enabling simultaneous chat and file transmission.
5) File transfer split into chunks, each chunk is encrypted, and a final SHA-256 checksum is verified at the receiver.
Message format:
[4-byte ciphertext length] [12-byte nonce | encrypted payload (+ AEAD tag)]
File transmissions:
   - A File Head message that includes filename and size.
   - Multiple File Chunk messages each containing partial data.
   - A File End message with the final SHA-256 digest.
Usage:
   1) Run the script (no arguments).
   2) Choose server or client mode.
   3) If server, input local address to listen on; if client, input server address to connect.
   4) Port defaults to 9999 if not specified.
   5) After secure channel is established, type messages or use "/file <path>" to send a file.
   6) Use "/quit" to exit.
"""
import socket
import struct
import threading
import hashlib
import pathlib
import os
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# Message types, each message starts with one byte indicating the type.  →
MSG_TYPE_TEXT = b'M'       
MSG_TYPE_FILE_HEAD = b'H'
MSG_TYPE_FILE_CHUNK = b'C'
MSG_TYPE_FILE_END = b'E'
FRAME_LENGTH_SIZE = 4       # 4 bytes for the encrypted frame length.  →
NONCE_LENGTH = 12           # 4-byte random prefix + 8-byte counter.  →
FILE_CHUNK_SIZE = 32 * 1024 # Each file chunk size in bytes.  →
def receive_exact(sock: socket.socket, amount: int) -> bytes:
    """
    Receive exactly 'amount' bytes from 'sock' or raise ConnectionError.  →
    """
    buffer_data = b''
    while len(buffer_data) < amount:
        chunk = sock.recv(amount - len(buffer_data))
        if not chunk:
            raise ConnectionError("Peer closed connection.")
        buffer_data += chunk
    return buffer_data
def send_all(sock: socket.socket, data: bytes) -> None:
    """
    Send all 'data' until complete using 'sock'.  →
    """
    view = memoryview(data)
    while view:
        sent = sock.send(view)
        view = view[sent:]
class ChaChaCipherContext:
    """
    Holds ChaCha20Poly1305 cipher state and a unique nonce generator.
    Nonce = 4-byte random prefix + 8-byte auto-increment counter.
    """
    def __init__(self, session_key: bytes):
        self.aead = ChaCha20Poly1305(session_key)       
        self.nonce_prefix = os.urandom(4)              
        self.nonce_counter = 0                         
        self.lock = threading.Lock()                   
    def generate_nonce(self) -> bytes:
        """
        Produce a fresh 12-byte nonce by combining prefix and big-endian counter.  →
        """
        with self.lock:
            counter_bytes = struct.pack(">Q", self.nonce_counter)
            self.nonce_counter = (self.nonce_counter + 1) & 0xFFFFFFFFFFFFFFFF
            return self.nonce_prefix + counter_bytes
    def encrypt_data(self, plaintext: bytes) -> bytes:
        """
        Encrypt data with unique nonce; returns nonce + ciphertext.  →
        """
        nonce = self.generate_nonce()
        ciphertext = self.aead.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_data(self, data: bytes) -> bytes:
        """
        Decrypt data by splitting the nonce from the ciphertext.  →
        """
        nonce = data[:NONCE_LENGTH]
        cipher_body = data[NONCE_LENGTH:]
        return self.aead.decrypt(nonce, cipher_body, None)

def send_frame(sock: socket.socket, cipher: ChaChaCipherContext, plaintext: bytes) -> None:
    """
    Encrypt 'plaintext' and send as a frame: 4-byte length + [nonce+ciphertext].  →
    """
    encrypted = cipher.encrypt_data(plaintext)
    header = struct.pack(">I", len(encrypted))
    send_all(sock, header + encrypted)

def receive_frame(sock: socket.socket, cipher: ChaChaCipherContext) -> bytes:
    """
    Receive a frame: read 4-byte length, then read the encrypted payload, then decrypt.  →
    """
    header_data = receive_exact(sock, FRAME_LENGTH_SIZE)
    total_len = struct.unpack(">I", header_data)[0]
    encrypted = receive_exact(sock, total_len)
    return cipher.decrypt_data(encrypted)

def perform_key_exchange(sock: socket.socket, is_server: bool) -> bytes:
    """
    Exchange X25519 ephemeral public keys and derive a 32-byte session key via HKDF.  →
    """
    local_private = X25519PrivateKey.generate()
    local_public_bytes = local_private.public_key().public_bytes()

    if is_server:
        # Server sends first
        send_all(sock, local_public_bytes)
        remote_public_bytes = receive_exact(sock, 32)
    else:
        # Client receives first
        remote_public_bytes = receive_exact(sock, 32)
        send_all(sock, local_public_bytes)

    remote_public_key = X25519PublicKey.from_public_bytes(remote_public_bytes)
    shared_secret = local_private.exchange(remote_public_key)    

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-terminal-chat"
    )
    session_key = hkdf.derive(shared_secret)
    return session_key

def send_file(sock: socket.socket, cipher: ChaChaCipherContext, file_path_str: str) -> None:
    """
    Send a file in HEAD, CHUNK, END messages. Validate with SHA-256.
    """
    path_obj = pathlib.Path(file_path_str)
    if not path_obj.is_file():
        print(f"File does not exist: {file_path_str}")  # → 
        return
    file_name_bytes = path_obj.name.encode('utf-8')
    file_size = path_obj.stat().st_size
    # FILE_HEAD
    head_msg = (
        MSG_TYPE_FILE_HEAD +
        struct.pack(">H", len(file_name_bytes)) +
        file_name_bytes +
        struct.pack(">Q", file_size)
    )
    send_frame(sock, cipher, head_msg)
    # Send chunks
    checksum = hashlib.sha256()
    with path_obj.open("rb") as opened_file:
        while True:
            chunk = opened_file.read(FILE_CHUNK_SIZE)
            if not chunk:
                break
            checksum.update(chunk)
            chunk_msg = (
                MSG_TYPE_FILE_CHUNK +
                struct.pack(">H", len(file_name_bytes)) +
                file_name_bytes +
                chunk
            )
            send_frame(sock, cipher, chunk_msg)
    # FILE_END
    digest = checksum.digest()
    end_msg = (
        MSG_TYPE_FILE_END +
        struct.pack(">H", len(file_name_bytes)) +
        file_name_bytes +
        digest
    )
    send_frame(sock, cipher, end_msg)
    print(f"File sent: {path_obj} ({file_size} bytes)")  # →
def handle_incoming_file(message: bytes, files_map: dict) -> None:
    """
    Handle FILE_HEAD, FILE_CHUNK, and FILE_END to reconstruct a file with integrity verified.  →
    """
    msg_type = message[:1]
    body = message[1:]

    if msg_type == MSG_TYPE_FILE_HEAD:
        name_length = struct.unpack(">H", body[:2])[0]
        file_name_str = body[2:2 + name_length].decode('utf-8', errors='ignore')
        file_size = struct.unpack(">Q", body[2 + name_length:2 + name_length + 8])[0]

        base_name = pathlib.Path(file_name_str).name
        target_path = pathlib.Path(base_name)
        idx = 1
        while target_path.exists():
            target_path = pathlib.Path(f"{base_name}_{idx}")
            idx += 1

        file_obj = target_path.open("wb")
        files_map[file_name_str] = {
            "fp": file_obj,
            "remain": file_size,
            "sha256": hashlib.sha256(),
            "savepath": target_path,
            "size": file_size,
            "received": 0
        }
        print(f"Receiving file: {file_name_str} ({file_size} bytes) -> {target_path}")  # →
    elif msg_type == MSG_TYPE_FILE_CHUNK:
        name_length = struct.unpack(">H", body[:2])[0]
        file_name_str = body[2:2 + name_length].decode('utf-8', errors='ignore')
        chunk_data = body[2 + name_length:]
        if file_name_str in files_map:
            info = files_map[file_name_str]
            info["fp"].write(chunk_data)
            info["sha256"].update(chunk_data)
            info["remain"] -= len(chunk_data)
            info["received"] += len(chunk_data)
            percent = 0
            if info["size"] > 0:
                percent = info["received"] / info["size"] * 100
            print(f"\r[{file_name_str}] {info['received']}/{info['size']} bytes ({percent:.1f}%)", end='', flush=True)  # →
    elif msg_type == MSG_TYPE_FILE_END:
        name_length = struct.unpack(">H", body[:2])[0]
        file_name_str = body[2:2 + name_length].decode('utf-8', errors='ignore')
        given_digest = body[2 + name_length:]
        if file_name_str in files_map:
            info = files_map.pop(file_name_str)
            info["fp"].close()
            real_digest = info["sha256"].digest()
            if real_digest == given_digest:
                print(f"\nFile received OK: {info['savepath']}")  # → 
            else:
                print(f"\nFile corrupted: {info['savepath']} (SHA-256 mismatch)")  # →
def receiver_thread(sock: socket.socket, cipher: ChaChaCipherContext) -> None:
    """
    Continuously receive frames, then dispatch to text or file logic.  →
    """
    incoming_files = {}
    try:
        while True:
            try:
                plain_data = receive_frame(sock, cipher)
            except ConnectionError:
                print("\n[Connection closed by peer.]")  # →
                break
            msg_type = plain_data[:1]
            if msg_type == MSG_TYPE_TEXT:
                text_str = plain_data[1:].decode('utf-8', errors='ignore')
                print(f"\n[Peer]: {text_str}")  # →
            elif msg_type in (MSG_TYPE_FILE_HEAD, MSG_TYPE_FILE_CHUNK, MSG_TYPE_FILE_END):
                handle_incoming_file(plain_data, incoming_files)
    except Exception as exc:
        print(f"\n[Receiver error]: {exc}")  # →
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()
        os._exit(0)
def sender_thread(sock: socket.socket, cipher: ChaChaCipherContext) -> None:
    """
    Reads user input, sends text or file. '/quit' to exit.  →
    """
    try:
        while True:
            line = input("> ")  # →
            if not line:
                continue
            if line == "/quit":
                break
            elif line.startswith("/file "):
                file_path = line[6:].strip()
                send_file(sock, cipher, file_path)
            else:
                plain_msg = MSG_TYPE_TEXT + line.encode('utf-8')
                send_frame(sock, cipher, plain_msg)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()
        os._exit(0)
def main() -> None:
    """
    Main function: ask user for server/client mode, address, port, then run secure chat.  →
    """
    print("=== Secure Terminal Chat + File Transfer ===")
    while True:
        mode = input("Type 'server' or 'client': ").strip().lower()
        if mode in ("server", "client"):
            break
    if mode == "server":
        default_addr = "0.0.0.0"
        address_str = input(f"Listen address [{default_addr}]: ").strip() or default_addr
        default_port = 9999
        port_str = input(f"Port [{default_port}]: ").strip() or str(default_port)
        port_int = int(port_str)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((address_str, port_int))
        server_socket.listen(1)
        print(f"[Server] Listening at {address_str}:{port_int} ...")
        conn, remote = server_socket.accept()
        print(f"[Server] Connected from {remote}")
        sock = conn
        is_server_flag = True
    else:
        default_addr = "127.0.0.1"
        address_str = input(f"Connect to host [{default_addr}]: ").strip() or default_addr
        default_port = 9999
        port_str = input(f"Port [{default_port}]: ").strip() or str(default_port)
        port_int = int(port_str)
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[Client] Connecting to {address_str}:{port_int} ...")
        client_socket.connect((address_str, port_int))
        print("[Client] Connected.")
        sock = client_socket
        is_server_flag = False
    # Key exchange to establish session key.  →
    session_key = perform_key_exchange(sock, is_server_flag)
    print("[Key exchange done, session is now secure]")
    cipher = ChaChaCipherContext(session_key)
    # Launch receiver thread.  →
    threading.Thread(target=receiver_thread, args=(sock, cipher), daemon=True).start()
    print("Enter text to chat, or '/file <path>' to send a file, or '/quit' to exit.")
    sender_thread(sock, cipher)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[User interrupted]")
"""
