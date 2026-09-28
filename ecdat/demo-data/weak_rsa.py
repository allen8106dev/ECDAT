# weak_rsa.py: Generates an RSA-2048 key pair for public-key cryptography.
# Classical RSA is vulnerable to quantum cryptanalysis via Shor's algorithm.
from Crypto.PublicKey import RSA

def generate_keypair() -> RSA.RsaKey:
    # Classical asymmetric key generation (RSA 2048-bit)
    key = RSA.generate(2048)
    return key

if __name__ == "__main__":
    key = generate_keypair()
    public_pem = key.publickey().export_key().decode("utf-8")
    first_line = public_pem.splitlines()[0]
    print(f"[RSA] Key generated successfully ({key.size_in_bits()} bits): {first_line}")
