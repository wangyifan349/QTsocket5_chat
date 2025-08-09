import socket
import threading
import struct
import select

class Socks5Handler(threading.Thread):
    def __init__(self, clientSock, clientAddr):
        super().__init__(daemon=True)
        self.clientSock = clientSock
        self.clientAddr = clientAddr

    def run(self):
        try:
            # Step 1: Perform SOCKS5 handshake
            if not self.doHandshake():
                self.clientSock.close()
                return

            # Step 2: Parse client request (only CONNECT supported)
            request = self.parseRequest()
            if request is None:
                self.clientSock.close()
                return
            destAddress, destPort = request

            # Step 3: Establish connection to target server
            remoteSock = self.connectTarget(destAddress, destPort)
            if remoteSock is None:
                self.clientSock.close()
                return

            # Step 4: Send success reply to client
            self.sendReply(0x00)

            # Step 5: Relay data between client and remote
            self.forwardData(self.clientSock, remoteSock)

        finally:
            self.clientSock.close()

    def doHandshake(self):
        """Receive and reply to the SOCKS5 greeting."""
        header = self.clientSock.recv(2)
        if len(header) < 2:
            return False
        version, methodCount = struct.unpack("!BB", header)
        if version != 0x05:
            return False
        # Discard offered methods
        self.clientSock.recv(methodCount)
        # Reply: SOCKS5 version, no authentication
        self.clientSock.sendall(struct.pack("!BB", 0x05, 0x00))
        return True

    def parseRequest(self):
        """Read the client CONNECT request and return (address, port)."""
        header = self.clientSock.recv(4)
        if len(header) < 4:
            return None
        version, command, reserved, addressType = struct.unpack("!BBBB", header)
        # Only support SOCKS5 CONNECT
        if version != 0x05 or command != 0x01:
            self.sendReply(0x07)  # Command not supported
            return None

        # Parse destination address
        if addressType == 0x01:  # IPv4
            addrBytes = self.clientSock.recv(4)
            destAddress = socket.inet_ntoa(addrBytes)
        elif addressType == 0x03:  # Domain name
            lengthByte = self.clientSock.recv(1)
            length = lengthByte[0]
            destAddress = self.clientSock.recv(length).decode()
        else:
            self.sendReply(0x08)  # Address type not supported
            return None

        # Parse destination port
        portBytes = self.clientSock.recv(2)
        destPort = struct.unpack("!H", portBytes)[0]
        return destAddress, destPort

    def connectTarget(self, address, port):
        """Attempt to connect to the target address and return the socket."""
        try:
            return socket.create_connection((address, port))
        except Exception:
            self.sendReply(0x05)  # Connection refused
            return None

    def sendReply(self, replyCode):
        """Send a SOCKS5 reply with the given reply code."""
        # VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
        reply = struct.pack("!BBBB", 0x05, replyCode, 0x00, 0x01)
        reply += socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
        self.clientSock.sendall(reply)

    def forwardData(self, sockA, sockB):
        """Relay data bi-directionally between sockA and sockB."""
        socketList = [sockA, sockB]
        while True:
            ready, _, _ = select.select(socketList, [], [])
            if sockA in ready:
                data = sockA.recv(4096)
                if not data:
                    break
                sockB.sendall(data)
            if sockB in ready:
                data = sockB.recv(4096)
                if not data:
                    break
                sockA.sendall(data)
        sockB.close()


def main(listenHost="0.0.0.0", listenPort=1080):
    # Create listening socket for incoming SOCKS5 clients
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSock.bind((listenHost, listenPort))
    serverSock.listen(128)
    print(f"SOCKS5 multithreaded TCP transparent proxy running on {listenHost}:{listenPort}")

    try:
        while True:
            clientSock, clientAddr = serverSock.accept()
            handler = Socks5Handler(clientSock, clientAddr)
            handler.start()
    finally:
        serverSock.close()


if __name__ == "__main__":
    main()
