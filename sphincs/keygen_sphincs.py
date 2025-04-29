import json
import hashlib
import pyspx.sha2_128s as sphincs  # SPHINCS+ variant: 128-bit security with SHA-2

def save_sphincs_keys(sk, pk, sk_file, pk_file):
    with open(sk_file, "w") as f:
        json.dump({"sk": sk.hex()}, f, indent=4)

    pk_hash = hashlib.sha256(pk).digest()
    with open(pk_file, "w") as f:
        json.dump({
            "pk": pk.hex(),
            "pk_hash": pk_hash.hex()
        }, f, indent=4)

def main():

    SkFile = "sphincs/sk_Sphincs.json"
    PkFile = "sphincs/pk_Sphincs.json"

    # Generació de claus
    pk, sk = sphincs.generate_keypair() # Funció de la llibreria

    save_sphincs_keys(sk, pk, SkFile, PkFile)
    print(f"Claus SPHINCS+ generades i guardades en {SkFile} i {PkFile}")

if __name__ == "__main__":
    main()
