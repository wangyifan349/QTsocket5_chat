import struct
import os
from typing import Tuple
class ChaCha20Poly1305:
    def __init__(self, key: bytes):
        """
        初始化 ChaCha20-Poly1305 加密解密器
        :param key: 32 字节密钥
        """
        if len(key) != 32:
            raise ValueError("Invalid key size")
        self.key = key
    def generate_nonce(self) -> bytes:
        """生成一个随机的 12 字节 nonce"""
        return os.urandom(12)
    # --------------------------- ChaCha20 ---------------------------
    def rotate_left(self, v: int, c: int) -> int:
        return ((v << c) & 0xffffffff) | (v >> (32 - c))
    def quarter_round(self, state: list[int], a: int, b: int, c: int, d: int) -> None:
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] ^= state[a]
        state[d] = self.rotate_left(state[d], 16)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] ^= state[c]
        state[b] = self.rotate_left(state[b], 12)
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] ^= state[a]
        state[d] = self.rotate_left(state[d], 8)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] ^= state[c]
        state[b] = self.rotate_left(state[b], 7)
    def chacha20_block(self, counter: int, nonce: bytes) -> bytes:
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"
        key_words = [struct.unpack('<I', self.key[i:i + 4])[0] for i in range(0, 32, 4)]
        nonce_words = [struct.unpack('<I', nonce[i:i + 4])[0] for i in range(0, 12, 4)]
        state = constants + key_words + [counter] + nonce_words
        working_state = state.copy()
        for _ in range(10):  # 20 rounds
            self.quarter_round(working_state, 0, 4, 8, 12)
            self.quarter_round(working_state, 1, 5, 9, 13)
            self.quarter_round(working_state, 2, 6, 10, 14)
            self.quarter_round(working_state, 3, 7, 11, 15)
            self.quarter_round(working_state, 0, 5, 10, 15)
            self.quarter_round(working_state, 1, 6, 11, 12)
            self.quarter_round(working_state, 2, 7, 8, 13)
            self.quarter_round(working_state, 3, 4, 9, 14)
        output = []
        for i in range(16):
            val = (working_state[i] + state[i]) & 0xffffffff
            output.append(struct.pack('<I', val))
        return b''.join(output)  # 64 bytes
    def chacha20_encrypt(self, plaintext: bytes, nonce: bytes, counter: int = 1) -> bytes:
        ciphertext = bytearray()
        for block_num in range((len(plaintext) + 63) // 64):
            block = plaintext[block_num * 64:(block_num + 1) * 64]
            keystream = self.chacha20_block(counter + block_num, nonce)
            for i in range(len(block)):
                ciphertext.append(block[i] ^ keystream[i])
        return bytes(ciphertext)
    # --------------------------- Poly1305 ---------------------------
    def clamp_r(self, r_bytes: bytes) -> bytes:
        r = list(r_bytes)
        r[3] &= 15
        r[7] &= 15
        r[11] &= 15
        r[15] &= 15
        r[4] &= 252
        r[8] &= 252
        r[12] &= 252
        return bytes(r)
    def le_bytes_to_num(self, bs: bytes) -> int:
        return sum(b << (8 * i) for i, b in enumerate(bs))
    def num_to_16_le_bytes(self, num: int) -> bytes:
        return b''.join(((num >> (8 * i)) & 0xff).to_bytes(1, 'little') for i in range(16))
    def poly1305_mac(self, msg: bytes, key: bytes) -> bytes:
        # key: 32 bytes = r(16) | s(16)
        r_raw = key[:16]
        s = key[16:]
        r = self.clamp_r(r_raw)
        r_num = self.le_bytes_to_num(r)
        s_num = self.le_bytes_to_num(s)
        p = (1 << 130) - 5
        acc = 0
        for i in range(0, len(msg), 16):
            block = msg[i:i + 16]
            n = self.le_bytes_to_num(block + b'\x01')  # pad 1
            acc = (acc + n) % p
            acc = (acc * r_num) % p
        acc = (acc + s_num) % (1 << 128)
        return self.num_to_16_le_bytes(acc)
    # --------------------------- 高级 API ---------------------------
    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        高级加密接口，自动生成 nonce
        :param plaintext: 明文数据
        :return: (nonce, ciphertext, tag) 随机生成的nonce，密文和认证标签
        """
        nonce = self.generate_nonce()
        # Step 1: 生成 Poly1305 密钥 
        poly_key = self.chacha20_block(0, nonce)[:32]
        # Step 2: 使用 ChaCha20 加密明文
        ciphertext = self.chacha20_encrypt(plaintext, nonce)
        # Step 3: 构造认证数据（密文 + 长度）
        mac_data = b''
        mac_data += ciphertext
        mac_data += struct.pack('<Q', len(ciphertext))
        # Step 4: 计算 Poly1305 MAC 标签
        tag = self.poly1305_mac(mac_data, poly_key)
        return nonce, ciphertext, tag
    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        高级解密接口
        :param nonce: 随机生成的 nonce
        :param ciphertext: 密文数据
        :param tag: 认证标签
        :return: 解密后的明文
        """
        # Step 1: 生成 Poly1305 密钥
        poly_key = self.chacha20_block(0, nonce)[:32]
        # 构造认证数据
        mac_data = b''
        mac_data += ciphertext
        mac_data += struct.pack('<Q', len(ciphertext))
        # Step 2: 校验 Poly1305 MAC 标签
        calc_tag = self.poly1305_mac(mac_data, poly_key)
        if calc_tag != tag:
            raise ValueError("Poly1305 tag mismatch! Decryption failed or authentication failed.")
        # Step 3: 使用 ChaCha20 解密密文
        return self.chacha20_encrypt(ciphertext, nonce)
# --------------------------- 示例 ---------------------------
if __name__ == '__main__':
    key = b'0123456789ABCDEF0123456789ABCDEF'  # 32 字节密钥
    plaintext = b"Hello, world!"
    print("Plaintext:", plaintext)
    # 创建加密器
    chacha_poly = ChaCha20Poly1305(key)
    # 加密
    nonce, ciphertext, tag = chacha_poly.encrypt(plaintext)
    print("Nonce (hex):", nonce.hex())
    print("Ciphertext (hex):", ciphertext.hex())
    print("Tag (hex):", tag.hex())
    # 解密并验证
    try:
        decrypted = chacha_poly.decrypt(nonce, ciphertext, tag)
        print("Decrypted text:", decrypted)
    except ValueError as e:
        print("Decryption failed:", e)
