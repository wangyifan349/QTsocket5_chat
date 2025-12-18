#!/usr/bin/env python3
# x25519_interactive_json.py
# Single-file interactive demo with JSON-framed encrypted payloads
# - Full-word variable names
# - Minimal function encapsulation
# - Interactive CLI
# - X25519 handshake + ChaCha20-Poly1305
# - Frames are length-prefixed JSON with base64 nonce and ciphertext
# Requirements: pip install cryptography
import socket
import threading
import struct
import os
import sys
import time
import json
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# send all bytes
def send_all_bytes(network_socket, data_bytes):
    total_sent = 0
    while total_sent < len(data_bytes):
        sent = network_socket.send(data_bytes[total_sent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        total_sent += sent
# receive exact bytes
def receive_exact_bytes(network_socket, count):
    buffer_out = bytearray()
    while len(buffer_out) < count:
        chunk = network_socket.recv(count - len(buffer_out))
        if not chunk:
            return b""
        buffer_out.extend(chunk)
    return bytes(buffer_out)
# length-prefixed frame send/receive (raw bytes)
def send_frame_bytes(network_socket, payload_bytes):
    send_all_bytes(network_socket, struct.pack("!I", len(payload_bytes)) + payload_bytes)
def receive_frame_bytes(network_socket):
    header = receive_exact_bytes(network_socket, 4)
    if not header:
        return b""
    (length_value,) = struct.unpack("!I", header)
    return receive_exact_bytes(network_socket, length_value)
# interactive read
def read_interactive_line(prompt_text):
    sys.stdout.write(prompt_text)
    sys.stdout.flush()
    line = sys.stdin.readline()
    if not line:
        return None
    return line.rstrip("\n")
# produce nonce bytes (12 bytes) from counter dict
def produce_nonce_bytes(counter_dict):
    current_value = counter_dict["value"]
    counter_dict["value"] = current_value + 1
    return (current_value).to_bytes(12, "little")
# helper to send JSON-wrapped encrypted frame
def send_encrypted_json_frame(network_socket, aead_cipher, nonce_counter_dict, plaintext_bytes, frame_type=None):
    nonce_bytes = produce_nonce_bytes(nonce_counter_dict)
    ciphertext_bytes = aead_cipher.encrypt(nonce_bytes, plaintext_bytes, None)
    json_object = {"nonce": base64.b64encode(nonce_bytes).decode(), "ct": base64.b64encode(ciphertext_bytes).decode()}
    if frame_type is not None:
        json_object["type"] = frame_type
    json_bytes = json.dumps(json_object, separators=(",", ":")).encode()
    send_frame_bytes(network_socket, json_bytes)
# helper to receive and parse JSON-wrapped encrypted frame and decrypt
def receive_encrypted_json_frame(network_socket, aead_cipher):
    json_bytes = receive_frame_bytes(network_socket)
    if not json_bytes:
        return None, None
    json_object = json.loads(json_bytes.decode())
    nonce_bytes = base64.b64decode(json_object["nonce"])
    ciphertext_bytes = base64.b64decode(json_object["ct"])
    plaintext_bytes = aead_cipher.decrypt(nonce_bytes, ciphertext_bytes, None)
    frame_type = json_object.get("type")
    return plaintext_bytes, frame_type
# main interactive program
def main():
    print("Choose mode: server or client")
    mode_line = read_interactive_line("> ")
    if mode_line is None:
        return
    mode_text = mode_line.strip().lower()
    if mode_text not in ("server", "client"):
        print("Invalid mode. Type 'server' or 'client'.")
        return
    if mode_text == "server":
        listen_address = "0.0.0.0"
        listen_port = 9000
        print("Server listening on {}:{}".format(listen_address, listen_port))
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.bind((listen_address, listen_port))
        listen_socket.listen(1)
        connection_socket, client_address = listen_socket.accept()
        print("Server accepted connection from", client_address)
        # X25519 handshake (server sends pub then reads client pub)
        server_private_key = x25519.X25519PrivateKey.generate()
        server_public_bytes = server_private_key.public_key().public_bytes()
        send_frame_bytes(connection_socket, server_public_bytes)
        client_public_bytes = receive_frame_bytes(connection_socket)
        if not client_public_bytes:
            print("Server: failed to receive client public key")
            connection_socket.close()
            return
        client_public_key = x25519.X25519PublicKey.from_public_bytes(client_public_bytes)
        shared_secret_bytes = server_private_key.exchange(client_public_key)
        derived_symmetric_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519 handshake").derive(shared_secret_bytes)
        aead_cipher = ChaCha20Poly1305(derived_symmetric_key)
        print("Server derived symmetric key:", derived_symmetric_key.hex()[:32], "...")
        nonce_counter = {"value": 0}
        # receiver thread for server
        def server_receive_loop():
            try:
                while True:
                    # receive next frame; it may be a control JSON frame indicating FILE_START (unencrypted)
                    frame_bytes = receive_frame_bytes(connection_socket)
                    if not frame_bytes:
                        print("Server: connection closed by peer")
                        break
                    # try parse as JSON control frame for file start (unencrypted)
                    # design: file transfer starts with a plain JSON like {"file_start":"filename"}
                    try:
                        parsed = json.loads(frame_bytes.decode())
                        if "file_start" in parsed:
                            filename = parsed["file_start"]
                            output_path = os.path.join(".", "received_" + filename)
                            with open(output_path, "wb") as out_file:
                                while True:
                                    plaintext_chunk, chunk_type = receive_encrypted_json_frame(connection_socket, aead_cipher)
                                    if plaintext_chunk is None:
                                        print("Server: connection closed during file receive")
                                        return
                                    if plaintext_chunk == b"":
                                        break
                                    out_file.write(plaintext_chunk)
                            print("Server: received file saved to", output_path)
                            continue
                    except Exception:
                        # not a plain JSON file-start control, treat as encrypted JSON frame (it should be)
                        pass
                    # if not file-start control, treat frame_bytes as encrypted JSON frame
                    try:
                        json_object = json.loads(frame_bytes.decode())
                        nonce_bytes = base64.b64decode(json_object["nonce"])
                        ciphertext_bytes = base64.b64decode(json_object["ct"])
                        plaintext_bytes = aead_cipher.decrypt(nonce_bytes, ciphertext_bytes, None)
                        frame_type = json_object.get("type")
                        if frame_type == "MSG":
                            print("Peer message:", plaintext_bytes.decode(errors="replace"))
                        else:
                            print("Server received unknown encrypted frame type:", frame_type)
                    except Exception as e:
                        print("Server: failed to parse/decrypt frame:", e)
            except Exception as e:
                print("Server receive exception:", e)
        threading.Thread(target=server_receive_loop, daemon=True).start()
        # server interactive send loop
        print("Server interactive mode. Commands:")
        print("  /sendfile <path>    send a file to peer")
        print("  any other text      send as message")
        while True:
            line_text = read_interactive_line("server> ")
            if line_text is None:
                break
            command_text = line_text.strip()
            if command_text == "":
                continue
            if command_text.lower().startswith("/sendfile "):
                file_path = command_text.split(" ", 1)[1].strip()
                if not os.path.isfile(file_path):
                    print("Server: file not found:", file_path)
                    continue
                base_name = os.path.basename(file_path)
                # send plain JSON file_start control
                control_object = {"file_start": base_name}
                send_frame_bytes(connection_socket, json.dumps(control_object, separators=(",", ":")).encode())
                # send encrypted chunks as JSON frames
                with open(file_path, "rb") as file_reader:
                    while True:
                        chunk_bytes = file_reader.read(4096)
                        if not chunk_bytes:
                            break
                        send_encrypted_json_frame(connection_socket, aead_cipher, nonce_counter, chunk_bytes, frame_type="FILE_CHUNK")
                # EOF marker as encrypted empty plaintext
                send_encrypted_json_frame(connection_socket, aead_cipher, nonce_counter, b"", frame_type="FILE_CHUNK")
                print("Server: file sent:", file_path)
            else:
                send_encrypted_json_frame(connection_socket, aead_cipher, nonce_counter, command_text.encode(), frame_type="MSG")
        connection_socket.close()
        listen_socket.close()
        print("Server exiting.")
    else:
        # client mode
        server_address = "127.0.0.1"
        server_port = 9000
        print("Client connecting to {}:{}".format(server_address, server_port))
        connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection_socket.connect((server_address, server_port))
        print("Client connected")
        # X25519 handshake (client reads server pub then sends client pub)
        client_private_key = x25519.X25519PrivateKey.generate()
        client_public_bytes = client_private_key.public_key().public_bytes()
        server_public_bytes = receive_frame_bytes(connection_socket)
        if not server_public_bytes:
            print("Client: failed to receive server public key")
            connection_socket.close()
            return
        send_frame_bytes(connection_socket, client_public_bytes)
        server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_bytes)
        shared_secret_bytes = client_private_key.exchange(server_public_key)
        derived_symmetric_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"x25519 handshake").derive(shared_secret_bytes)
        aead_cipher = ChaCha20Poly1305(derived_symmetric_key)
        print("Client derived symmetric key:", derived_symmetric_key.hex()[:32], "...")
        nonce_counter = {"value": 0}
        # client receive loop
        def client_receive_loop():
            try:
                while True:
                    frame_bytes = receive_frame_bytes(connection_socket)
                    if not frame_bytes:
                        print("Client: connection closed by peer")
                        break
                    # check plain JSON control for file_start
                    try:
                        parsed = json.loads(frame_bytes.decode())
                        if "file_start" in parsed:
                            filename = parsed["file_start"]
                            output_path = os.path.join(".", "received_" + filename)
                            with open(output_path, "wb") as out_file:
                                while True:
                                    plaintext_chunk, chunk_type = receive_encrypted_json_frame(connection_socket, aead_cipher)
                                    if plaintext_chunk is None:
                                        print("Client: connection closed during file receive")
                                        return
                                    if plaintext_chunk == b"":
                                        break
                                    out_file.write(plaintext_chunk)
                            print("Client: received file saved to", output_path)
                            continue
                    except Exception:
                        pass
                    # otherwise treat as encrypted JSON frame
                    try:
                        json_object = json.loads(frame_bytes.decode())
                        nonce_bytes = base64.b64decode(json_object["nonce"])
                        ciphertext_bytes = base64.b64decode(json_object["ct"])
                        plaintext_bytes = aead_cipher.decrypt(nonce_bytes, ciphertext_bytes, None)
                        frame_type = json_object.get("type")
                        if frame_type == "MSG":
                            print("Peer message:", plaintext_bytes.decode(errors="replace"))
                        else:
                            print("Client received unknown encrypted frame type:", frame_type)
                    except Exception as e:
                        print("Client: failed to parse/decrypt frame:", e)
            except Exception as e:
                print("Client receive exception:", e)
        threading.Thread(target=client_receive_loop, daemon=True).start()
        # client interactive send loop
        print("Client interactive mode. Commands:")
        print("  /sendfile <path>    send a file to server")
        print("  any other text      send as message")
        while True:
            line_text = read_interactive_line("client> ")
            if line_text is None:
                break
            command_text = line_text.strip()
            if command_text == "":
                continue
            if command_text.lower().startswith("/sendfile "):
                file_path = command_text.split(" ", 1)[1].strip()
                if not os.path.isfile(file_path):
                    print("Client: file not found:", file_path)
                    continue
                base_name = os.path.basename(file_path)
                control_object = {"file_start": base_name}
                send_frame_bytes(connection_socket, json.dumps(control_object, separators=(",", ":")).encode())
                with open(file_path, "rb") as file_reader:
                    while True:
                        chunk_bytes = file_reader.read(4096)
                        if not chunk_bytes:
                            break
                        send_encrypted_json_frame(connection_socket, aead_cipher, nonce_counter, chunk_bytes, frame_type="FILE_CHUNK")
                send_encrypted_json_frame(connection_socket, aead_cipher, nonce_counter, b"", frame_type="FILE_CHUNK")
                print("Client: file sent:", file_path)
            else:
                send_encrypted_json_frame(connection_socket, aead_cipher, nonce_counter, command_text.encode(), frame_type="MSG")

        connection_socket.close()
        print("Client exiting.")
if __name__ == "__main__":
    main()
