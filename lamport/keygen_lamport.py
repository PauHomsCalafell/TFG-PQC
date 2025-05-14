import hashlib
import secrets
import json
import os

N_BITS = 256 # Ja que utilitzo SHA-256
SEED_SIZE = 32   # 32 bytes = 256 bits per seed (preimatge)


def H(data):
    """
    Descripció: Aplica SHA-256 sobre les dades d'entrada.
    Args: data (bytes): Dades a hashejar.
    Return: bytes: Digest SHA-256.
    """
    return hashlib.sha256(data).digest()




def lamport_keygen():
    """ Descripció: Genera un parell de claus secretes i públiques Lamport OTS.
        Return: tuple: (sk0, sk1, pk0, pk1) on:
                sk0, sk1: llistes de claus secretes (256 elements).
                pk0, pk1: llistes de claus públiques corresponents.
    """

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
    """
        Guarda les claus Lamport en fitxers JSON.
        Args:   sk0 (list[bytes]): Claus secretes sk0.
                sk1 (list[bytes]): Claus secretes sk1.
                pk0 (list[bytes]): Claus públiques pk0.
                pk1 (list[bytes]): Claus públiques pk1.
                SK_filename (str): Ruta del fitxer on guardar les claus secretes.
                PK_filename (str): Ruta del fitxer on guardar les claus públiques.
    """

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
    """
    Genera i guarda claus Lamport. Crea la carpeta 'lamport' i escriu les claus
    generades en fitxers JSON.
    """

    os.makedirs("lamport", exist_ok=True)
    
    # Fitxers on es guarden les claus
    SkFile = "lamport/sk_Lamport.json"
    PkFile = "lamport/pk_Lamport.json"

    # Generació
    sk0, sk1, pk0, pk1 = lamport_keygen()

    # Guardar
    save_lamport_key(sk0, sk1, pk0, pk1, SkFile, PkFile)
    print(f"Claus Lamport generades i guardades en {SkFile} i {PkFile}")


if __name__ == "__main__":
    main()
