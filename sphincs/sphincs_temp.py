import os
import json
import hashlib
import secrets

# Son proves i tests de SPHINCS+ pero per poder tenir alguna cosa per provar Merkle!!

def generate_sphincs_keypair():
   
    sk = secrets.token_bytes(64)  # Clau privada falsa (placeholder)
    pk = secrets.token_bytes(32)  # Clau pública falsa (placeholder)
    return pk, sk

def save_sphincs_keys(sk, pk, sk_file, pk_file):
    with open(sk_file, "w") as f:
        json.dump({"sk": sk.hex()}, f, indent=4)

    pk_hash = hashlib.sha256(pk).hexdigest()

    with open(pk_file, "w") as f:
        json.dump({
            "pk_hash": pk_hash,
            "pk": pk.hex()
        }, f, indent=4)

def main():
    
    os.makedirs("sphincs", exist_ok=True)

    sk_file = "sphincs/sk_SPHINCS.json"
    pk_file = "sphincs/pk_SPHINCS.json"

    pk, sk = generate_sphincs_keypair()
    save_sphincs_keys(sk, pk, sk_file, pk_file)

    print(f"Claus SPHINCS+ simulades guardades a {pk_file} i {sk_file}")

if __name__ == "__main__":
    main()
