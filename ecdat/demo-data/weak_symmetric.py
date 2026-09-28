# weak_symmetric.py: Demonstrates obsolete symmetric encryption using DES.
# DES has a short 56-bit key length and is vulnerable to brute-force attacks.
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    # Insecure legacy cipher: DES block size is 8 bytes
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, DES.block_size))

if __name__ == "__main__":
    secret_key = b"8bytekey"  # DES requires an 8-byte key
    data = b"Sample legacy sensitive payload"
    ciphertext = encrypt_data(data, secret_key)
    print(f"[DES] Encrypted data (hex): {ciphertext.hex()}")

