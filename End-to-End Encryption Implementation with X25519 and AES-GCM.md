# 🚀 End-to-End Encryption (E2EE) in Practice: X25519 + AES-GCM

## 📖 1. Background & Goals  
1. Why use E2EE?  
   - 🔒 Ensure messages remain confidential from “Sender” to “Receiver”  
   - 👀 Prevent man-in-the-middle or server-side eavesdropping and tampering  
2. What this document covers:  
   - Use **X25519** to perform secure Diffie–Hellman key agreement  
   - Use the derived symmetric key for **AES-GCM** encryption/decryption  

---

## 🔑 2. Algorithm Overview  

1. X25519 (Curve25519 ECDH)  
   - Based on a Montgomery curve for high performance and side-channel resistance  
   - Each party generates a key pair, exchanges public keys, and computes the same shared secret  
2. AES-GCM (Galois/Counter Mode)  
   - AES provides confidentiality; GCM provides integrity/authentication  
   - Decryption automatically verifies the authentication tag; failure indicates tampering or a wrong key  

---

## ⚙️ 3. High-Level Flow  

1. Each party generates an X25519 key pair  
2. Public Key A ↔︎ Public Key B are exchanged over any channel  
3. Each side computes `shared = X25519(own_priv, peer_pub)`  
4. Run HKDF over `shared` to derive:  
   - 32-byte AES-256-GCM key  
   - 12-byte GCM IV  
5. Use AES-GCM to encrypt the plaintext → yields `ciphertext + tag`  
6. The recipient uses the same Key/IV/(optional AAD) to decrypt and authenticate  

---

## 🔍 4. Details & Caveats  

- Private Keys: **Must** be securely stored and never exposed  
- Public Keys: Can be openly transmitted but **must** be protected against tampering  
- HKDF:  
  - Use SHA-256 as the underlying hash  
  - `length = key_length + iv_length` (here 32 + 12 = 44 bytes)  
- IV Reuse Risk:  
  - Reusing the same Key+IV in GCM breaks security  
  - Ensure IV uniqueness per session or per message  
- Additional Authenticated Data (AAD):  
  - Optional, binds metadata (e.g. message ID, timestamp) into the authentication tag  

---

## 🛠️ 5. Python Reference Implementation  

```python
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_x25519_key_pair():
    # Generate an X25519 private/public key pair
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(local_private_key: x25519.X25519PrivateKey,
                          peer_public_key: x25519.X25519PublicKey) -> bytes:
    # Compute the 32-byte shared secret via Diffie–Hellman
    return local_private_key.exchange(peer_public_key)

def derive_key_and_iv(shared_secret: bytes) -> tuple[bytes, bytes]:
    # Derive 32-byte AES key + 12-byte IV using HKDF-SHA256
    hkdf = HKDF(algorithm=hashes.SHA256(), length=44, salt=None, info=b'handshake')
    key_iv = hkdf.derive(shared_secret)
    return key_iv[:32], key_iv[32:]

def encrypt(plaintext: bytes, aes_key: bytes, aes_iv: bytes) -> bytes:
    # AES-256-GCM encryption (no AAD); returns ciphertext || tag
    aesgcm = AESGCM(aes_key)
    return aesgcm.encrypt(aes_iv, plaintext, associated_data=None)

def decrypt(ciphertext: bytes, aes_key: bytes, aes_iv: bytes) -> bytes:
    # AES-256-GCM decryption (no AAD); verifies tag automatically
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(aes_iv, ciphertext, associated_data=None)

def main():
    # Generate key pairs for Party A and Party B
    private_key_a, public_key_a = generate_x25519_key_pair()
    private_key_b, public_key_b = generate_x25519_key_pair()
    # Compute shared secrets and verify they match
    shared_secret_a = compute_shared_secret(private_key_a, public_key_b)
    shared_secret_b = compute_shared_secret(private_key_b, public_key_a)
    assert shared_secret_a == shared_secret_b, "Shared secrets do not match!"
    # Derive AES key and IV from shared secret
    aes_key, aes_iv = derive_key_and_iv(shared_secret_a)
    # Encrypt and decrypt a sample message
    message = b"Attack at dawn!"
    ciphertext = encrypt(message, aes_key, aes_iv)
    print("Ciphertext (hex):", ciphertext.hex())
    decrypted_message = decrypt(ciphertext, aes_key, aes_iv)
    print("Decrypted message:", decrypted_message)

main()

```

---

## 🔒 6. Security Best Practices  

- Rotate (ephemeral) X25519 key pairs for each session to limit exposure  
- Sign public keys or use certificates to prevent man-in-the-middle attacks  
- Enforce IV uniqueness/randomness in production systems  
- For post-quantum resistance, consider integrating PQC algorithms  

---

😊 You now have a complete, logical guide to:  
- X25519 key agreement  
- Deriving symmetric keys & IV via HKDF  
- Encrypting/decrypting with AES-GCM  

Feel free to extend this with “re-keying,” “multi-round handshakes,” or “message batching” to fit your protocol.
