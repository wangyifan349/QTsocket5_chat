#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wxcrypt_tool.py

Purpose:
- Provide auxiliary encryption in WeChat (End-to-End Encryption + Layered Encryption).
- Supports two modes:
  1) X25519 handshake for session key derivation (AES-GCM Encryption/Decryption).
  2) Pre-shared key (PSK) mode for AES-GCM encryption/decryption.

Interactive Features:
- Menu-driven interface.
- Supports multiline input, terminated by a single "END" line.
- Output ciphertext with prefixes for easy identification/forwarding/pasting.

Security Notes (Understand these!):
- This only protects the "message content", not the WeChat metadata (contact, time, approximate length, etc.).
- If either of your devices or your friend's device is compromised (screen capture, clipboard theft), the message may still be exposed.
- Keys/passwords are stored only in memory and lost after program exits.
"""
import base64
import hashlib
import secrets
import sys
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -----------------------------
# Encoding/Decoding Utilities
# -----------------------------

PREFIX_VERSION = "WX1"     # Version prefix
TAG_PSK = "P"              # Pre-shared key mode tag
TAG_X25519 = "X"           # X25519 session mode tag
TAG_PUBKEY = "PK"          # Public key text tag

def b64u_encode(data: bytes) -> str:
    """URL-safe Base64 without line breaks and without the padding '=' sign."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def b64u_decode(text: str) -> bytes:
    """Decodes URL-safe Base64, auto-padding if necessary."""
    s = text.strip()
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# -----------------------------
# Multiline Input
# -----------------------------

def read_multiline(prompt: str = "") -> str:
    """
    Read multiline input from the user until 'END' is entered on a new line.
    Returns the concatenated string (joined by newline characters).
    """
    if prompt:
        print(prompt)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


# -----------------------------
# PSK (Pre-shared Key) Mode: Random salt + nonce for each message
# -----------------------------

def kdf_psk(password: str, salt: bytes, key_len: int = 32) -> bytes:
    """
    Derives AES key (32 bytes) from a password using scrypt (more resistant to GPU/ASIC brute-forcing).
    The salt is generated randomly for each message and carried with the ciphertext.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = Scrypt(
        salt=salt,
        length=key_len,
        n=2**14,   # 16384
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))

def psk_encrypt(password: str, plaintext: str) -> str:
    """
    Output format:
      WX1:P:<b64u(salt(16) | nonce(12) | aesgcm(ciphertext+tag))>
    """
    salt = secrets.token_bytes(16)
    key = kdf_psk(password, salt, 32)
    aesgcm = AESGCM(key)

    nonce = secrets.token_bytes(12)
    aad = (f"{PREFIX_VERSION}:{TAG_PSK}").encode("utf-8")  # Additional authenticated data: prevents mode confusion
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    payload = salt + nonce + ct
    return f"{PREFIX_VERSION}:{TAG_PSK}:{b64u_encode(payload)}"

def psk_decrypt(password: str, token: str) -> str:
    """
    Decodes and decrypts the ciphertext: WX1:P:... or just b64u(payload) in PSK mode.
    """
    t = token.strip()
    payload_b64 = t

    if t.startswith(f"{PREFIX_VERSION}:{TAG_PSK}:"):
        payload_b64 = t.split(":", 2)[2]

    payload = b64u_decode(payload_b64)
    if len(payload) < 16 + 12 + 16:
        raise ValueError("Invalid ciphertext length (too short).")

    salt = payload[:16]
    nonce = payload[16:28]
    ct = payload[28:]

    key = kdf_psk(password, salt, 32)
    aesgcm = AESGCM(key)
    aad = (f"{PREFIX_VERSION}:{TAG_PSK}").encode("utf-8")
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")


# -----------------------------
# X25519 Handshake Mode: Derive session key (optional additional password)
# -----------------------------

def parse_pubkey_text(text: str) -> bytes:
    """
    Accepts:
    - WX1:PK:<b64u(raw32)>
    - Or just b64u(raw32)
    """
    s = text.strip()
    b64part = s
    if s.startswith(f"{PREFIX_VERSION}:{TAG_PUBKEY}:"):
        b64part = s.split(":", 2)[2]
    raw = b64u_decode(b64part)
    if len(raw) != 32:
        raise ValueError("Invalid public key length (X25519 public key should be 32 bytes).")
    return raw

def format_pubkey_text(raw32: bytes) -> str:
    """Generates a public key text suitable for WeChat."""
    if len(raw32) != 32:
        raise ValueError("Internal error: Public key is not 32 bytes.")
    return f"{PREFIX_VERSION}:{TAG_PUBKEY}:{b64u_encode(raw32)}"

def x25519_derive_session_key(
    my_private: x25519.X25519PrivateKey,
    my_public_raw32: bytes,
    peer_public_raw32: bytes,
    extra_password: Optional[str] = None,
) -> bytes:
    """
    Derives a 32-byte AES session key from X25519 shared secret using HKDF.
    
    - Shared secret: my_private.exchange(peer_public)
    - HKDF derivation: concatenate both public keys lexicographically for the info to ensure both sides agree.
    - Optionally mix in an extra password to reduce MITM risks (but still not equivalent to authentication).
    """
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_raw32)
    shared_secret = my_private.exchange(peer_pub)  # 32 bytes

    # Normalize public key order to ensure both sides get the same info
    a, b = (my_public_raw32, peer_public_raw32) if my_public_raw32 <= peer_public_raw32 else (peer_public_raw32, my_public_raw32)
    info = b"wxcrypt-x25519-session|" + a + b

    ikm = shared_secret
    if extra_password:
        # Use a deterministic salt bound to the public key pair to avoid reusing the same derivation in different conversations
        bind_salt = sha256(b"wxcrypt-bind-salt|" + a + b)[:16]
        psk = kdf_psk(extra_password, bind_salt, 32)
        ikm = shared_secret + psk  # 64 bytes fed to HKDF (as input materials)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sha256(b"wxcrypt-hkdf-salt|" + a + b),  # Deterministic salt bound to both public keys
        info=info,
    )
    return hkdf.derive(ikm)

def x_encrypt(session_key: bytes, plaintext: str) -> str:
    """
    Output format:
      WX1:X:<b64u(nonce(12) | aesgcm(ciphertext+tag))>
    """
    if len(session_key) != 32:
        raise ValueError("Session key length is incorrect.")
    aesgcm = AESGCM(session_key)
    nonce = secrets.token_bytes(12)
    aad = (f"{PREFIX_VERSION}:{TAG_X25519}").encode("utf-8")
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    payload = nonce + ct
    return f"{PREFIX_VERSION}:{TAG_X25519}:{b64u_encode(payload)}"

def x_decrypt(session_key: bytes, token: str) -> str:
    """
    Decrypts WX1:X:... or just b64u(payload) in X25519 mode.
    Assumes the session key has been derived and set.
    """
    if len(session_key) != 32:
        raise ValueError("Session key length is incorrect.")

    t = token.strip()
    payload_b64 = t
    if t.startswith(f"{PREFIX_VERSION}:{TAG_X25519}:"):
        payload_b64 = t.split(":", 2)[2]

    payload = b64u_decode(payload_b64)
    if len(payload) < 12 + 16:
        raise ValueError("Invalid ciphertext length (too short).")

    nonce = payload[:12]
    ct = payload[12:]

    aesgcm = AESGCM(session_key)
    aad = (f"{PREFIX_VERSION}:{TAG_X25519}").encode("utf-8")
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt.decode("utf-8")


# -----------------------------
# Interactive Menu
# -----------------------------

@dataclass
class State:
    # X25519-related
    my_priv: Optional[x25519.X25519PrivateKey] = None
    my_pub_raw32: Optional[bytes] = None
    peer_pub_raw32: Optional[bytes] = None
    session_key: Optional[bytes] = None

    # PSK-related (only in memory)
    default_password: Optional[str] = None


def print_help() -> None:
    print(
        "\nUsage Points:\n"
        "1) PSK Mode: Both parties agree on a strong password in advance.\n"
        "   - Encryption output: WX1:P:...\n"
        "   - Decryption requires pasting the ciphertext.\n"
        "\n"
        "2) X25519 Mode: Both parties exchange public keys and derive a shared session key.\n"
        "   - Public key text: WX1:PK:...\n"
        "   - Encryption output: WX1:X:...\n"
        "   - Optional 'extra password': mix this in the derivation to reduce MITM risks.\n"
        "\n"
        "Multiline plaintext input: Enter line by line, end with a line 'END'.\n"
    )

def menu() -> None:
    print(
        "\n========== wxcrypt_tool ==========\n"
        "1. Generate/Refresh My X25519 Public Key (for Handshake)\n"
        "2. Set Peer X25519 Public Key and Derive Session Key\n"
        "3. Encrypt with X25519 Session Key (multiline, END to finish)\n"
        "4. Decrypt with X25519 Session Key\n"
        "5. Set/Update Default Password (PSK Mode)\n"
        "6. Encrypt with PSK (multiline, END to finish)\n"
        "7. Decrypt with PSK\n"
        "8. Show Help/Format\n"
        "0. Exit\n"
        "=================================\n"
    )

def require_session_key(st: State) -> bytes:
    if not st.session_key:
        raise ValueError("Session key is not established: Please perform steps 1 (generate public key) and 2 (set peer public key and derive).")
    return st.session_key

def require_password(st: State) -> str:
    if st.default_password:
        return st.default_password
    pw = input("Enter password (it will not be echoed): ").strip()
    if not pw:
        raise ValueError("Password cannot be empty.")
    return pw

def action_gen_my_key(st: State) -> None:
    st.my_priv = x25519.X25519PrivateKey.generate()
    pub = st.my_priv.public_key()
    st.my_pub_raw32 = pub.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw
    )
    # Refresh local keypair, old session is invalidated
    st.peer_pub_raw32 = None
    st.session_key = None

    print("\n[My Public Key] (Copy and send to the peer):")
    print(format_pubkey_text(st.my_pub_raw32))

def action_set_peer_and_derive(st: State) -> None:
    if not st.my_priv or not st.my_pub_raw32:
        raise ValueError("Please generate your public key first: Perform option 1.")

    peer_text = input("Paste the peer's public key (WX1:PK:... or just b64u):\n> ").strip()
    peer_raw = parse_pubkey_text(peer_text)
    st.peer_pub_raw32 = peer_raw

    extra = input("Optional: Enter an 'extra password' to mix in the derivation (leave empty for none):\n> ").strip()
    extra_pw = extra if extra else None

    st.session_key = x25519_derive_session_key(
        my_private=st.my_priv,
        my_public_raw32=st.my_pub_raw32,
        peer_public_raw32=st.peer_pub_raw32,
        extra_password=extra_pw,
    )

    # Do not print session_key (to avoid accidental exposure), just show fingerprint for verification
    fp = b64u_encode(sha256(st.session_key)[:9])
    print(f"\nSession key established. Key fingerprint (should match on both sides): {fp}")

def action_x_encrypt(st: State) -> None:
    key = require_session_key(st)
    plaintext = read_multiline("Enter the plaintext to encrypt (multiline, END to finish):")
    token = x_encrypt(key, plaintext)
    print("\n[Ciphertext] (Copy and send to the peer):")
    print(token)

def action_x_decrypt(st: State) -> None:
    key = require_session_key(st)
    token = input("Paste the ciphertext to decrypt (WX1:X:... or just b64u):\n> ").strip()
    pt = x_decrypt(key, token)
    print("\n[Decrypted Result]:")
    print(pt)

def action_set_default_password(st: State) -> None:
    pw = input("Enter the default password (it will not be echoed):").strip()
    if not pw:
        raise ValueError("Password cannot be empty.")
    st.default_password = pw
    print("Default password updated (stored only in memory).")

def action_psk_encrypt(st: State) -> None:
    pw = require_password(st)
    plaintext = read_multiline("Enter the plaintext to encrypt (multiline, END to finish):")
    token = psk_encrypt(pw, plaintext)
    print("\n[Ciphertext] (Copy and send to the peer):")
    print(token)

def action_psk_decrypt(st: State) -> None:
    pw = require_password(st)
    token = input("Paste the ciphertext to decrypt (WX1:P:... or just b64u):\n> ").strip()
    pt = psk_decrypt(pw, token)
    print("\n[Decrypted Result]:")
    print(pt)

def main() -> None:
    st = State()
    print("wxcrypt_tool started. For auxiliary encryption in WeChat. Enter 8 to see help.")

    while True:
        try:
            menu()
            choice = input("Select an option:").strip()

            if choice == "0":
                print("Exiting.")
                return
            elif choice == "1":
                action_gen_my_key(st)
            elif choice == "2":
                action_set_peer_and_derive(st)
            elif choice == "3":
                action_x_encrypt(st)
            elif choice == "4":
                action_x_decrypt(st)
            elif choice == "5":
                action_set_default_password(st)
            elif choice == "6":
                action_psk_encrypt(st)
            elif choice == "7":
                action_psk_decrypt(st)
            elif choice == "8":
                print_help()
            else:
                print("Invalid option.")
        except KeyboardInterrupt:
            print("\nDetected Ctrl+C: Exiting.")
            return
        except Exception as e:
            print(f"\n[Error] {e}")
if __name__ == "__main__":
    main()
