# safe_modern.py: Safe modern cryptography using SHA-256 and AES-256.
# Provides collision resistance and robust 256-bit symmetric encryption.
import hashlib
import os
from Crypto.Cipher import AES

def hash_data(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def encrypt_aes256(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext

if __name__ == "__main__":
    sample = b"Confidential modern data payload"
    print(f"[SHA-256] Digest: {hash_data(sample)}")
    aes_key = os.urandom(32)  # 256-bit key
    nonce, ciphertext = encrypt_aes256(aes_key, sample)
    print(f"[AES-256-GCM] Ciphertext: {ciphertext.hex()[:32]}...")

