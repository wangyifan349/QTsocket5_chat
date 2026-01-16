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

import sys                                                   # 导入系统模块，用于与解释器及系统交互
import os                                                    # 操作系统接口
import socket                                                # 套接字，用于网络通信
import struct                                                # 提供打包与解包二进制数据(此处用于长度/nonce处理)
import hashlib                                               # 提供SHA-256等哈希函数
import threading                                             # 用于多线程
import pathlib                                               # 提供面向对象的文件路径处理

from PyQt5.QtCore import Qt, QThread, pyqtSignal             # Qt 核心库（线程、信号）
from PyQt5.QtWidgets import (                                # PyQt5 图形界面组件
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
    QPushButton, QTextEdit, QFileDialog, QVBoxLayout, QHBoxLayout,
    QRadioButton, QGroupBox, QButtonGroup
)
from PyQt5.QtGui import QPalette, QColor                     # PyQt5 调色板和颜色类

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey  # X25519 密钥
from cryptography.hazmat.primitives.kdf.hkdf import HKDF                     # HKDF 用于密钥扩展
from cryptography.hazmat.primitives import hashes                             # 包含 SHA-256 等哈希算法
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305      # ChaCha20-Poly1305 AEAD 加密算法

# Constants for message types and frame sizes.  ←
MessageTypeText = b'M'                                   # 表示文本消息
MessageTypeFileHead = b'H'                               # 表示文件头（名称、大小）
MessageTypeFileChunk = b'C'                              # 表示文件块内容
MessageTypeFileEnd = b'E'                                # 表示文件结束(附带SHA-256校验)

FrameLengthSize = 4                                      # 每帧最开始4字节表示加密后数据的总长度
NonceLength = 12                                         # Nonce长度(4字节随机+8字节计数器)
FileChunkSize = 32 * 1024                                # 每次读取或发送文件的块大小(32KB)

class NetworkThread(QThread):                            # 继承QThread，用于后台执行网络操作
    """
    NetworkThread class handles all socket operations:
    1) Server or client setup (TCP).
    2) X25519 ephemeral key exchange + HKDF to get ChaCha20Poly1305 key.
    3) Encrypting and decrypting data frames.
    4) Handling both chat messages and file transmissions in a background thread.
    """

    signalLog = pyqtSignal(str)                          # 用于在UI上显示日志输出
    signalConnected = pyqtSignal(bool)                   # 是否成功连接或发生异常
    signalMessage = pyqtSignal(str)                      # 接收到的文本消息
    signalFileStart = pyqtSignal(str, int, str)          # 文件开始: 文件名, 文件大小, 存储路径
    signalFileProgress = pyqtSignal(str, int, int)       # 文件进度: 文件名, 已接收字节数, 总大小
    signalFileFinish = pyqtSignal(str, bool, str)        # 文件结束: 文件名, 是否成功校验, 存储路径

    def __init__(self, startupMode, hostAddress, portNumber, parent=None):
        super().__init__(parent)                         # 调用父类构造
        self.startupMode = startupMode                   # 字符串 "server"/"client"
        self.hostAddress = hostAddress                   # IP 地址或域名
        self.portNumber = portNumber                     # 端口号
        self.networkSocket = None                        # 存储建立的socket
        self.threadRunning = True                        # 用于控制线程循环
        self.aeadCipher = None                           # ChaCha20Poly1305 加解密实例
        self.noncePrefixBytes = None                     # 4字节随机前缀
        self.nonceCounter = 0                            # 8字节计数器
        self.incomingFilesMap = {}                       # 用于临时存储正在接收的文件信息

    def run(self):
        """
        The main logic executed by QThread. Sets up server or client, handles key exchange, 
        then loops receiving packets until disconnection or error.  ←
        """
        try:
            if self.startupMode == "server":                                # 如果是服务器模式
                serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建TCP socket
                serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 允许端口重用
                serverSocket.bind((self.hostAddress, self.portNumber))            # 绑定所需地址和端口
                serverSocket.listen(1)                                            # 开始监听，等待客户端连接
                self.signalLog.emit(f"[Server] Listening at {self.hostAddress}:{self.portNumber} ...") 
                connection, addressInfo = serverSocket.accept()                   # 阻塞等待连接
                self.networkSocket = connection                                  # 保存套接字
                self.signalLog.emit(f"[Server] Connected from {addressInfo}")     # 日志输出连接信息
            else:                                                                # 客户端模式
                self.signalLog.emit(f"[Client] Connecting to {self.hostAddress}:{self.portNumber} ...")
                clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建TCP socket
                clientSocket.connect((self.hostAddress, self.portNumber))         # 主动连接服务器
                self.networkSocket = clientSocket                                # 保存套接字
                self.signalLog.emit("[Client] Connection established")            # 通知连接成功

            self.performKeyExchange()                                            # 执行一次X25519+HKDF来建立加密通道

            self.signalConnected.emit(True)                                      # 通知UI已成功连接

            while self.threadRunning:                                            # 开始循环接收数据
                frameData = self.receiveFrame()                                  # 尝试接收并解密一帧
                if not frameData:                                                # 如果没有数据，表示对端断开
                    break
                self.processReceivedMessage(frameData)                           # 解析并处理该消息

        except Exception as exceptionInfo:                                       # 出现任何异常
            self.signalLog.emit("[!] Connection or thread error: " + str(exceptionInfo))
            self.signalConnected.emit(False)                                     # 通知UI连接失败
        finally:
            if self.networkSocket:                                               # 清理连接
                self.networkSocket.close()
            self.threadRunning = False                                           # 标记线程结束

    def performKeyExchange(self):
        """
        Performs ephemeral X25519 key exchange:
        1) Generate ephemeral private key.
        2) If in server mode, send pubKey first, then receive. Else, receive first, then send.
        3) Derive a 32-byte session key by HKDF(SHA256).
        4) Initialize ChaCha20Poly1305 with that session key.
        """
        privateKey = X25519PrivateKey.generate()                  # 生成临时私钥
        localPubBytes = privateKey.public_key().public_bytes()    # 获取公钥字节

        if self.startupMode == "server":                          # 服务器先发公钥，再收对方公钥
            self.sendAll(localPubBytes)
            remotePub = self.receiveExact(32)
        else:                                                     # 客户端先收对方公钥，再发自身公钥
            remotePub = self.receiveExact(32)
            self.sendAll(localPubBytes)

        remoteKey = X25519PublicKey.from_public_bytes(remotePub)  # 解析对方公钥
        sharedSecret = privateKey.exchange(remoteKey)             # 计算共享密钥(32字节)

        # 使用HKDF派生出会话对称密钥(32字节)
        hkdfProcessor = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"secure-chat-pyqt"
        )
        sessionKey = hkdfProcessor.derive(sharedSecret)

        self.aeadCipher = ChaCha20Poly1305(sessionKey)            # 初始化AEAD加密器
        self.noncePrefixBytes = os.urandom(4)                     # 生成4字节随机前缀
        self.nonceCounter = 0                                     # 计数器归零

        self.signalLog.emit("[+] Secure channel established (X25519 + ChaCha20Poly1305)") # 通知UI

    def buildNonce(self) -> bytes:
        """
        Builds a unique nonce = 4-byte random prefix + 8-byte big-endian counter.
        """
        counterBytes = struct.pack(">Q", self.nonceCounter)     # 将计数器转换为8字节大端
        self.nonceCounter = (self.nonceCounter + 1) & 0xFFFFFFFFFFFFFFFF  # 递增并防止溢出
        return self.noncePrefixBytes + counterBytes             # 拼合成12字节nonce

    def encryptData(self, plaintext: bytes) -> bytes:
        """
        Encrypts data with ChaCha20Poly1305. Returns 12-byte nonce + ciphertext.  ←
        """
        nonceBytes = self.buildNonce()                                       # 先生成nonce
        cipherText = self.aeadCipher.encrypt(nonceBytes, plaintext, None)    # AEAD加密
        return nonceBytes + cipherText                                      # 返回nonce+密文

    def decryptData(self, encryptedData: bytes) -> bytes:
        """
        Decrypts data by splitting out the 12-byte nonce from the ciphertext.  ←
        """
        nonceBytes = encryptedData[:NonceLength]        # 提取前12字节nonce
        cipherBody = encryptedData[NonceLength:]        # 剩余是实际密文+MAC
        return self.aeadCipher.decrypt(nonceBytes, cipherBody, None)  # 解密得到原文

    def sendFrame(self, plaintext: bytes):
        """
        Encrypts and sends a frame: [4-byte length][12-byte nonce + ciphertext].  ←
        """
        enc = self.encryptData(plaintext)                  # 先加密
        header = struct.pack(">I", len(enc))               # 打包4字节表示这帧的长度
        self.sendAll(header + enc)                         # 依次发送长度和密文

    def receiveFrame(self) -> bytes:
        """
        Receives an encrypted frame, then decrypts it. Returns plaintext.  ←
        """
        lengthHeader = self.receiveExact(FrameLengthSize)   # 先收4字节长度
        if not lengthHeader:                                # 若为空表示连接断开
            return b''
        totalLen = struct.unpack(">I", lengthHeader)[0]     # 解包长度值
        encryptedFrame = self.receiveExact(totalLen)        # 再收指定字节数的加密数据
        return self.decryptData(encryptedFrame)             # 解密后返回明文

    def sendAll(self, data: bytes):
        """
        Sends all data over the socket until complete.  ←
        """
        if self.networkSocket:                     # 若socket存在
            self.networkSocket.sendall(data)       # 使用sendall确保全部发送

    def receiveExact(self, size: int) -> bytes:
        """
        Receives 'size' bytes exactly from the socket, 
        or raises ConnectionError if the peer closes.  ←
        """
        bufferData = b''
        while len(bufferData) < size:                           # 循环直到接收满size字节
            chunk = self.networkSocket.recv(size - len(bufferData))
            if not chunk:                                       # 对端断开
                raise ConnectionError("Remote side closed the connection.")
            bufferData += chunk
        return bufferData

    def processReceivedMessage(self, messageData: bytes):
        """
        Distinguishes the message type and handles accordingly.
        For file, it uses a dictionary to store partial data and finalize at the end.  ←
        """
        messageType = messageData[:1]                      # 首字节为消息类型
        bodyData = messageData[1:]                         # 其余部分为payload

        if messageType == MessageTypeText:                 # 若是文本消息
            textString = bodyData.decode('utf-8', errors='ignore')
            self.signalMessage.emit(textString)            # 发出信号给UI

        elif messageType == MessageTypeFileHead:           # 文件头信息
            fileNameLength = struct.unpack(">H", bodyData[:2])[0]   # 文件名长度
            fileNameString = bodyData[2:2 + fileNameLength].decode('utf-8', errors='ignore')
            fileSize = struct.unpack(">Q", bodyData[2 + fileNameLength:2 + fileNameLength + 8])[0]

            baseFileName = pathlib.Path(fileNameString).name         # 提取干净的文件名
            targetPath = pathlib.Path(baseFileName)
            indexCount = 1
            while targetPath.exists():                                # 防止重名覆盖
                targetPath = pathlib.Path(f"{baseFileName}_{indexCount}")
                indexCount += 1

            openedFile = targetPath.open("wb")                        # 以二进制写方式打开文件
            self.incomingFilesMap[fileNameString] = {                 # 在映射中保存文件信息
                "fileObject": openedFile,
                "remainBytes": fileSize,
                "sha256Digest": hashlib.sha256(),
                "filePath": str(targetPath),
                "sizeBytes": fileSize,
                "receivedBytes": 0
            }
            self.signalFileStart.emit(fileNameString, fileSize, str(targetPath))  # 通知UI

        elif messageType == MessageTypeFileChunk:   # 文件块
            fileNameLength = struct.unpack(">H", bodyData[:2])[0]
            fileNameString = bodyData[2:2 + fileNameLength].decode('utf-8', errors='ignore')
            chunkData = bodyData[2 + fileNameLength:]
            if fileNameString in self.incomingFilesMap:               # 若在列表中
                infoDict = self.incomingFilesMap[fileNameString]
                fobj = infoDict["fileObject"]
                fobj.write(chunkData)                                 # 写入文件
                infoDict["sha256Digest"].update(chunkData)            # 更新hash
                infoDict["remainBytes"] -= len(chunkData)
                infoDict["receivedBytes"] += len(chunkData)
                self.signalFileProgress.emit(fileNameString, infoDict["receivedBytes"], infoDict["sizeBytes"])

        elif messageType == MessageTypeFileEnd:     # 文件结束
            fileNameLength = struct.unpack(">H", bodyData[:2])[0]
            fileNameString = bodyData[2:2 + fileNameLength].decode('utf-8', errors='ignore')
            fileDigest = bodyData[2 + fileNameLength:]
            if fileNameString in self.incomingFilesMap:               # 查找对应的文件信息
                infoDict = self.incomingFilesMap.pop(fileNameString)
                fobj = infoDict["fileObject"]
                fobj.close()                                          # 关闭文件
                realDigest = infoDict["sha256Digest"].digest()
                successCheck = (fileDigest == realDigest)             # 对比sha256哈希是否一致
                self.signalFileFinish.emit(fileNameString, successCheck, infoDict["filePath"])

    def sendText(self, textContent: str):
        """
        Public method to send a text message to the peer.  ←
        """
        if not self.aeadCipher:                      # 若加密器还未初始化
            return
        plainMessage = MessageTypeText + textContent.encode('utf-8')  # 拼装文本消息
        self.sendFrame(plainMessage)                                   

    def sendFile(self, filePathName: str):
        """
        Public method to send a file in chunks, plus a final SHA-256.  ←
        """
        pathObject = pathlib.Path(filePathName)
        if not pathObject.is_file():                                # 判断文件是否存在
            self.signalLog.emit(f"[!] File not found: {filePathName}")
            return

        fileNameBytes = pathObject.name.encode('utf-8')             # 提取文件名字节
        fileSize = pathObject.stat().st_size                        # 获取文件大小

        # Step 1: Send File Head
        headMessage = (MessageTypeFileHead +
                       struct.pack(">H", len(fileNameBytes)) +
                       fileNameBytes +
                       struct.pack(">Q", fileSize))
        self.sendFrame(headMessage)

        # Step 2: Send File Chunks and do SHA-256
        localSha256 = hashlib.sha256()
        with pathObject.open("rb") as readingFile:                  # 二进制读
            while True:
                chunk = readingFile.read(FileChunkSize)            # 循环读取
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
        super().__init__()                                        # 调用父类构造函数
        self.setWindowTitle("Secure Chat (X25519 + ChaCha20Poly1305)")  # 设置窗口标题
        self.resize(800, 600)                                     # 设置初始大小

        # Set color theme using QPalette.  ←
        mainPalette = QPalette()                                  # 创建调色板
        mainPalette.setColor(QPalette.Window, QColor("#FFF8DC"))  # 背景：cornsilk(淡金色)
        mainPalette.setColor(QPalette.Base, QColor("#F5FFFA"))    # 文本输入背景：mintcream(淡绿色)
        mainPalette.setColor(QPalette.AlternateBase, QColor("#FFFFE0")) # 备用色
        self.setPalette(mainPalette)                              # 应用到窗口

        # Mode selection group
        self.radioServerMode = QRadioButton("Server Mode")        # 单选按钮：服务器模式
        self.radioClientMode = QRadioButton("Client Mode")        # 单选按钮：客户端模式
        self.radioServerMode.setChecked(True)                     # 默认选中服务器
        self.buttonGroupMode = QButtonGroup()                     # 组合以互斥
        self.buttonGroupMode.addButton(self.radioServerMode)
        self.buttonGroupMode.addButton(self.radioClientMode)

        self.hostAddressLineEdit = QLineEdit("127.0.0.1")         # 默认地址
        self.portNumberLineEdit = QLineEdit("9999")               # 默认端口
        self.startConnectionButton = QPushButton("Start or Connect")  # 按钮

        modeLayout = QHBoxLayout()                                # 水平布局存放模式控件
        modeLayout.addWidget(self.radioServerMode)
        modeLayout.addWidget(self.radioClientMode)
        modeLayout.addWidget(QLabel("Host:"))
        modeLayout.addWidget(self.hostAddressLineEdit)
        modeLayout.addWidget(QLabel("Port:"))
        modeLayout.addWidget(self.portNumberLineEdit)
        modeLayout.addWidget(self.startConnectionButton)

        modeGroupBox = QGroupBox("Startup Mode")                  # 分组框
        modeGroupBox.setLayout(modeLayout)

        # Chat log and controls
        self.chatLogTextEdit = QTextEdit()                        # 聊天记录显示
        self.chatLogTextEdit.setReadOnly(True)                    # 只读，用户不可编辑

        self.messageLineEdit = QLineEdit()                        # 用于输入聊天消息
        self.sendMessageButton = QPushButton("Send Message")      # 发送消息按钮
        self.sendFileButton = QPushButton("Send File")            # 发送文件按钮

        bottomLayout = QHBoxLayout()                              # 底部水平布局
        bottomLayout.addWidget(self.messageLineEdit)
        bottomLayout.addWidget(self.sendMessageButton)
        bottomLayout.addWidget(self.sendFileButton)

        mainLayout = QVBoxLayout()                                # 垂直布局，将分组框、聊天记录、底部操作放一起
        mainLayout.addWidget(modeGroupBox)
        mainLayout.addWidget(self.chatLogTextEdit)
        mainLayout.addLayout(bottomLayout)

        containerWidget = QWidget()                               # 基础容器
        containerWidget.setLayout(mainLayout)                     # 设置布局
        self.setCentralWidget(containerWidget)                    # 设为中心窗口

        # Thread reference
        self.networkThread = None                                 # 存放 NetworkThread 实例

        # Signals
        self.startConnectionButton.clicked.connect(self.handleConnectClicked) # 当点击按钮时执行函数
        self.sendMessageButton.clicked.connect(self.handleSendClicked)        # 同理
        self.sendFileButton.clicked.connect(self.handleFileClicked)

    def handleConnectClicked(self):
        """
        Called when Start/Connect button is pressed. Sets up and starts the background thread.  ←
        """
        if self.networkThread and self.networkThread.isRunning():          # 若线程存在且在运行
            self.chatLogTextEdit.append("Already running or connected.")   # 提示
            return

        currentMode = "server" if self.radioServerMode.isChecked() else "client"  # 判断所选模式
        hostStr = self.hostAddressLineEdit.text().strip()                  # 读取地址
        portVal = int(self.portNumberLineEdit.text().strip())              # 读取端口

        self.networkThread = NetworkThread(currentMode, hostStr, portVal)  # 创建线程实例
        self.networkThread.signalLog.connect(self.logAppend)               # 关联日志信号
        self.networkThread.signalConnected.connect(self.handleConnected)   # 关联连接状态信号
        self.networkThread.signalMessage.connect(self.handlePeerMessage)   # 关联接收消息信号
        self.networkThread.signalFileStart.connect(self.handleFileStart)   # 关联文件开始信号
        self.networkThread.signalFileProgress.connect(self.handleFileProgress) # 文件进度
        self.networkThread.signalFileFinish.connect(self.handleFileFinish) # 文件完成
        self.networkThread.start()                                         # 启动线程

    def logAppend(self, text: str):
        """
        Appends a line of text to the chat log.  ←
        """
        self.chatLogTextEdit.append(text)    # 在聊天记录中追加文本

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
        self.chatLogTextEdit.append(f"<Peer>: {text}")  # 显示对方消息

    def handleFileStart(self, fileName: str, fileSize: int, savePath: str):
        """
        Called when an incoming file is about to be received.  ←
        """
        self.chatLogTextEdit.append(f"Receiving file: {fileName} ({fileSize} bytes) -> {savePath}")

    def handleFileProgress(self, fileName: str, receivedBytes: int, totalBytes: int):
        """
        Called as chunks of file data arrive.  ←
        """
        pct = float(receivedBytes) / float(totalBytes) * 100 if totalBytes else 0  # 计算百分比
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
        if not self.networkThread or not self.networkThread.isRunning():      # 若线程不存在或未运行
            self.chatLogTextEdit.append("Not connected, cannot send.")
            return
        textToSend = self.messageLineEdit.text().strip()                     # 获取输入的文本
        if textToSend:
            self.networkThread.sendText(textToSend)                          # 通过线程发送
            self.chatLogTextEdit.append(f"<Me>: {textToSend}")               # 本地也显示
            self.messageLineEdit.clear()                                     # 清空输入框

    def handleFileClicked(self):
        """
        Opens a file dialog and, if chosen, sends the selected file.  ←
        """
        if not self.networkThread or not self.networkThread.isRunning():
            self.chatLogTextEdit.append("Not connected, cannot send file.")
            return
        fileName, _ = QFileDialog.getOpenFileName(self, "Select File")  # 弹出文件选择对话框
        if fileName:
            self.chatLogTextEdit.append(f"Sending file: {fileName}")
            self.networkThread.sendFile(fileName)                       # 调用线程的发送文件函数

def MainEntryPoint():
    """
    Main entry point for launching the PyQt application.  ←
    """
    applicationObject = QApplication(sys.argv)  # 创建QApplication对象
    mainWindow = MainWindow()                   # 创建主窗口
    mainWindow.show()                           # 显示主窗口
    sys.exit(applicationObject.exec_())         # 进入事件循环

if __name__ == "__main__":
    MainEntryPoint()                            # 如果是主入口，则调用MainEntryPoint()


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
