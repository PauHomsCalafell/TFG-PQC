import os
import json
import hashlib
import secrets

# Son proves i tests de SPHINCS+ pero per poder tenir alguna cosa per provar Merkle!!

def generate_sphincs_keypair():
    """
    Simula la generació d’un parell de claus SPHINCS+ (no real).
    Returns:
        tuple:
            pk (bytes): Clau pública (simulada, 32 bytes).
            sk (bytes): Clau privada (simulada, 64 bytes).
    """
   
    sk = secrets.token_bytes(64)  # Clau privada falsa (placeholder)
    pk = secrets.token_bytes(32)  # Clau pública falsa (placeholder)
    return pk, sk

def save_sphincs_keys(sk, pk, sk_file, pk_file):
    """
    Guarda les claus SPHINCS+ simulades en fitxers JSON.
    Args:
        sk (bytes): Clau privada.
        pk (bytes): Clau pública.
        sk_file (str): Ruta del fitxer on guardar la clau privada.
        pk_file (str): Ruta del fitxer on guardar la clau pública.
    """

    with open(sk_file, "w") as f:
        json.dump({"sk": sk.hex()}, f, indent=4)

    pk_hash = hashlib.sha256(pk).hexdigest()

    with open(pk_file, "w") as f:
        json.dump({
            "pk_hash": pk_hash,
            "pk": pk.hex()
        }, f, indent=4)

def main():
    """
    Simula la generació i guarda les claus SPHINCS+ dins la carpeta 'sphincs'.
    """
    
    os.makedirs("sphincs", exist_ok=True)

    sk_file = "sphincs/sk_SPHINCS.json"
    pk_file = "sphincs/pk_SPHINCS.json"

    pk, sk = generate_sphincs_keypair()
    save_sphincs_keys(sk, pk, sk_file, pk_file)

    print(f"Claus SPHINCS+ simulades guardades a {pk_file} i {sk_file}")

if __name__ == "__main__":
    main()
