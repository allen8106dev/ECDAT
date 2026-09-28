# weak_hashing.py: Demonstrates weak password hashing using MD5.
# MD5 is obsolete and vulnerable to collision and pre-image attacks.
import hashlib

def hash_password(password: str) -> str:
    # Insecure cryptographic hash: MD5 produces 128-bit digests
    hasher = hashlib.md5()
    hasher.update(password.encode("utf-8"))
    return hasher.hexdigest()

if __name__ == "__main__":
    raw_password = "UserSecretPassword2026!"
    digest = hash_password(raw_password)
    print(f"[MD5] Hashed password: {digest}")

