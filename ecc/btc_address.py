import hashlib
from cryptography.hazmat.primitives import serialization

# Carrega la clau pública ECC en format bytes
def load_public_key(path="ecc/ecc_public_key.pem"):
    with open(path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    public_numbers = public_key.public_numbers()
    x = public_numbers.x.to_bytes(32, byteorder='big')
    y = public_numbers.y.to_bytes(32, byteorder='big')
    
    pubkey_bytes = b'\x04' + x + y  # Format no comprimit
    return pubkey_bytes

# Fa un hash160 (SHA256 -> RIPEMD160) de la clau pública
def hash160(data):
    sha = hashlib.sha256(data).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    return ripe

def main():
    pubkey_bytes = load_public_key()
    pubkey_hash160 = hash160(pubkey_bytes)

    print("Hash160 de la clau publica (Fake Bitcoin address hash):")
    print(pubkey_hash160.hex())

if __name__ == "__main__":
    main()
