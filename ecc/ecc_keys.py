import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Llegeix l'arrel de Merkle des del fitxer
def load_merkle_root(path="merkle_ecc/root_merkle.json"):
    with open(path, "r") as f:
        data = json.load(f)
    return bytes.fromhex(data["merkle_root"])

# Deriva una clau ECC a partir del hash de l’arrel
def generate_ecc_key_from_merkle_root(root):
    sk_hash = hashlib.sha256(root).digest()
    sk_int = int.from_bytes(sk_hash, "big") % ec.SECP256R1().key_size

    # Crea la clau privada ECC (escalada al rang vàlid)
    private_key = ec.derive_private_key(sk_int, ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Desa les claus en fitxers PEM
def save_keys_to_pem(private_key, public_key, folder):

    # Clau privada
    with open(f"{folder}/ecc_private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Clau pública
    with open(f"{folder}/ecc_public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def main():
    
    os.makedirs("ecc", exist_ok=True)

    merkle_root = load_merkle_root()
    private_key, public_key = generate_ecc_key_from_merkle_root(merkle_root)
    save_keys_to_pem(private_key, public_key, "ecc")

    print("Clau ECC derivada de l’arrel Merkle creada correctament.")
    print("Guardada a ecc/ecc_private_key.pem i ecc/ecc_public_key.pem")

if __name__ == "__main__":
    main()
