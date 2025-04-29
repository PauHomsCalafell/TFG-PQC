import hashlib
import secrets
import json
import os

N_BITS = 256 # Ja que utilitzo SHA-256
SEED_SIZE = 32   # 32 bytes = 256 bits per seed (preimatge)

# Funció hash
def H(data):
    return hashlib.sha256(data).digest()

def lamport_keygen():

    sk0, sk1, pk0, pk1 = [], [], [], []
    
    for _ in range(N_BITS):
        seed0 = secrets.token_bytes(SEED_SIZE)
        seed1 = secrets.token_bytes(SEED_SIZE)
        
        sk0.append(seed0)
        sk1.append(seed1)
        
        pk0.append(H(seed0))
        pk1.append(H(seed1))
    
    return sk0, sk1, pk0, pk1


def save_lamport_key(sk0, sk1, pk0, pk1, SK_filename, PK_filename):

    # S'ha de convertir a hex per guardar-la
    sk_data = {
        "sk0": [s.hex() for s in sk0],
        "sk1": [s.hex() for s in sk1],
    }

    # Creació del hash per la posterior utilització en Merkle
    pk_hash = H(b''.join(pk0 + pk1))

    pk_data = {
        "pk_hash": pk_hash.hex(),
        "pk0": [p.hex() for p in pk0],
        "pk1": [p.hex() for p in pk1],
    }
    with open(SK_filename, "w") as f:
        json.dump(sk_data, f, indent=4)

    with open(PK_filename, "w") as f:
        json.dump(pk_data, f, indent=4)


def main():

    os.makedirs("lamport", exist_ok=True)
    
    # Fitxers on es guarden les claus
    SkFile = "lamport/sk_Lamport.json"
    PkFile = "lamport/pk_Lamport.json"

    # Generació
    sk0, sk1, pk0, pk1 = lamport_keygen()

    # Guardar
    save_lamport_key(sk0, sk1, pk0, pk1, SkFile, PkFile)
    print(f"Claus generades i guardades en {SkFile} i {PkFile}")


if __name__ == "__main__":
    main()
