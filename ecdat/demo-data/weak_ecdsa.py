# weak_ecdsa.py: Generates an ECDSA key and signs a message.
# Elliptic curve cryptography is vulnerable to quantum attacks (Shor's algorithm).
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def sign_message(message: bytes) -> bytes:
    # Classical elliptic curve key generation and ECDSA signing
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

if __name__ == "__main__":
    payload = b"Authentic banking transaction receipt"
    sig = sign_message(payload)
    print(f"[ECDSA] Signature produced ({len(sig)} bytes): {sig[:16].hex()}...")

