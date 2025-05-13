import hashlib
import secrets
import json
import os

# Nombre de bits que es volen signar amb Lamport (normalment SHA-256 → 256 bits)
N_BITS = 256
SEED_SIZE = 32  # Mida de cada preimatge (clau privada): 32 bytes = 256 bits

def H(data):
    """
    Descripció: Aplica SHA-256 sobre les dades d'entrada.
    Args: data (bytes): Dades a hashejar.
    Return: bytes: Digest SHA-256.
    """
    return hashlib.sha256(data).digest()

def lamport_keygen():
    """
    Genera un parell de claus Lamport OTS (sk0, sk1, pk0, pk1).
    Return:
        tuple: Llistes de claus secretes i públiques.
    """
    sk0, sk1, pk0, pk1 = [], [], [], []
    for _ in range(N_BITS):
        s0 = secrets.token_bytes(SEED_SIZE)
        s1 = secrets.token_bytes(SEED_SIZE)
        sk0.append(s0)
        sk1.append(s1)
        pk0.append(H(s0))
        pk1.append(H(s1))
    return sk0, sk1, pk0, pk1

def hash_lamport_pk(pk0, pk1):
    """
    Agrega i fa hash de la clau pública Lamport.
    Args:
        pk0 (list[bytes]): Part de la clau pública per bits 0.
        pk1 (list[bytes]): Part de la clau pública per bits 1.
    Return:
        bytes: Hash global de la clau pública.
    """
    data = b''.join(pk0 + pk1)
    return H(data)

def build_merkle_tree(leaf_nodes):
    """
    Construeix un arbre de Merkle a partir dels fulles.
    Args:
        leaf_nodes (list[bytes]): Llistat de hashes de claus públiques.
    Return:
        list[list[bytes]]: Llista de nivells de l’arbre.
    """
    tree = [leaf_nodes[:]]
    while len(tree[-1]) > 1:
        prev_level = tree[-1]
        new_level = []
        for i in range(0, len(prev_level), 2):
            left = prev_level[i]
            right = prev_level[i+1]
            new_level.append(H(left + right))
        tree.append(new_level)
    return tree

def get_auth_path(tree, index):
    """
    Obté el camí d'autenticació (auth path) des d'una fulla de Merkle.
    Args:
        tree (list[list[bytes]]): Arbre de Merkle.
        index (int): Índex de la fulla.
    Return:
        list[bytes]: Llista de nodes germans per autenticar.
    """
    path = []
    for level in tree[:-1]:
        sibling_index = index ^ 1  # node germà (XOR amb 1)
        path.append(level[sibling_index])
        index //= 2
    return path

# Generació de totes les claus (Lamport) i arbre de Merkle
def mss_keygen(h=4):
    """
    Genera claus Lamport i construeix l’arbre de Merkle (MSS).
    Args:
        h (int): Alçada de l’arbre de Merkle (2^h fulles).
    Return:
        tuple: (lamport_keys, tree, root) per signatura i verificació.
    """
    num_keys = 2**h
    lamport_keys = []
    leaf_hashes = []

    for _ in range(num_keys):
        sk0, sk1, pk0, pk1 = lamport_keygen()
        lamport_keys.append((sk0, sk1, pk0, pk1))
        leaf_hashes.append(hash_lamport_pk(pk0, pk1))

    tree = build_merkle_tree(leaf_hashes)
    root = tree[-1][0]  # l’arrel és l’únic node de l’últim nivell
    return lamport_keys, tree, root

# Guarda claus privades i arrel de Merkle en fitxers JSON
def save_mss_keys(lamport_keys, root, sk_filename, pk_filename):
    """
    Guarda claus MSS i l'arrel en fitxers JSON.
    Args:
        lamport_keys (list): Claus Lamport generades.
        root (bytes): Arrel de l’arbre Merkle.
        sk_filename (str): Fitxer per la clau privada.
        pk_filename (str): Fitxer per la clau pública.
    """

    private_data = {
        "lamport_keys": [
            {
                "sk0": [s.hex() for s in sk0],
                "sk1": [s.hex() for s in sk1],
                "pk0": [p.hex() for p in pk0],
                "pk1": [p.hex() for p in pk1],
            }
            for (sk0, sk1, pk0, pk1) in lamport_keys
        ]
    }

    with open(sk_filename, "w") as f:
        json.dump(private_data, f, indent=4)

    public_data = {
        "pk_hash": H(root).hex(),
        "root": root.hex()
    }

    with open(pk_filename, "w") as f:
        json.dump(public_data, f, indent=4)


def main():
    """
    Genera claus MSS (Lamport + Merkle) i les guarda en fitxers JSON.
    """
    
    os.makedirs("mss_lots", exist_ok=True)

    # Fitxers on es guarden les claus
    SkFile = "mss_lots/sk_MSS.json"
    PkFile = "mss_lots/pk_MSS.json"

    # Generació
    lamport_keys, tree, root = mss_keygen(h=3)  # 2^3 = 8 claus Lamport (fulles)

    # Guardar
    save_mss_keys(lamport_keys, root, SkFile, PkFile)
    print(f"Claus generades i guardades en {SkFile} i {PkFile}")

if __name__ == "__main__":
    main()
