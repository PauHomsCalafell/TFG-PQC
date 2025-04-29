import hashlib
import secrets
import json
import os

# Nombre de bits que es volen signar amb Lamport (normalment SHA-256 → 256 bits)
N_BITS = 256
SEED_SIZE = 32  # Mida de cada preimatge (clau privada): 32 bytes = 256 bits

# Funció hash (SHA-256)
def H(data):
    return hashlib.sha256(data).digest()

# Generació de claus Lamport OTS
def lamport_keygen():
    sk0, sk1, pk0, pk1 = [], [], [], []
    for _ in range(N_BITS):
        s0 = secrets.token_bytes(SEED_SIZE)
        s1 = secrets.token_bytes(SEED_SIZE)
        sk0.append(s0)
        sk1.append(s1)
        pk0.append(H(s0))
        pk1.append(H(s1))
    return sk0, sk1, pk0, pk1

# Firma Lamport d’un missatge (digest de 256 bits)
def lamport_sign(message, sk0, sk1):
    sig = []
    for i in range(N_BITS):
        byte_index = i // 8
        bit_index = 7 - (i % 8)
        bit = (message[byte_index] >> bit_index) & 1
        sig.append(sk0[i] if bit == 0 else sk1[i])
    return sig

# Verificació de la firma Lamport
def lamport_verify(message, sig, pk0, pk1):
    for i in range(N_BITS):
        byte_index = i // 8
        bit_index = 7 - (i % 8)
        bit = (message[byte_index] >> bit_index) & 1
        hashed = H(sig[i])
        if (bit == 0 and hashed != pk0[i]) or (bit == 1 and hashed != pk1[i]):
            return False
    return True

# Hash de la clau pública Lamport (concatena tots els pk0 i pk1 i obté un hash global)
def hash_lamport_pk(pk0, pk1):
    data = b''.join(pk0 + pk1)
    return H(data)

# Construcció de l’arbre de Merkle a partir de les fulles (hash de claus públiques)
def build_merkle_tree(leaf_nodes):
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

# Obtenció del camí d’autenticació (auth path) des de una fulla fins a l’arrel
def get_auth_path(tree, index):
    path = []
    for level in tree[:-1]:
        sibling_index = index ^ 1  # node germà (XOR amb 1)
        path.append(level[sibling_index])
        index //= 2
    return path

# Recalcular l’arrel de l’arbre donat un camí d’autenticació
def compute_root_from_auth(leaf, auth_path, index):
    current = leaf
    for sibling in auth_path:
        if index % 2 == 0:
            current = H(current + sibling)
        else:
            current = H(sibling + current)
        index //= 2
    return current

# Generació de totes les claus (Lamport) i arbre de Merkle
def mss_keygen(h=4):
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

# Signatura d’un missatge amb una clau Lamport concreta (índex de fulla)
def mss_sign(message, lamport_keys, tree, index):
    sk0, sk1, pk0, pk1 = lamport_keys[index]
    sig = lamport_sign(message, sk0, sk1)
    pk = (pk0, pk1)
    auth_path = get_auth_path(tree, index)
    return index, sig, pk, auth_path

# Verificació completa (firma Lamport + autenticació Merkle)
def mss_verify(message, index, sig, pk, auth_path, root):
    pk0, pk1 = pk
    if not lamport_verify(message, sig, pk0, pk1):
        return False
    leaf = hash_lamport_pk(pk0, pk1)
    recomputed_root = compute_root_from_auth(leaf, auth_path, index)
    return recomputed_root == root

# Guarda claus privades i arrel de Merkle en fitxers JSON
def save_mss_keys(lamport_keys, root, sk_filename, pk_filename):

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

# Carrega claus des de fitxers JSON
def load_mss_keys(sk_filename, pk_filename):
    with open(sk_filename, "r") as f:
        private_data = json.load(f)

    lamport_keys = []
    for entry in private_data["lamport_keys"]:
        sk0 = [bytes.fromhex(x) for x in entry["sk0"]]
        sk1 = [bytes.fromhex(x) for x in entry["sk1"]]
        pk0 = [bytes.fromhex(x) for x in entry["pk0"]]
        pk1 = [bytes.fromhex(x) for x in entry["pk1"]]
        lamport_keys.append((sk0, sk1, pk0, pk1))

    with open(pk_filename, "r") as f:
        public_data = json.load(f)
    root = bytes.fromhex(public_data["root"])

    return lamport_keys, root

def main():
    
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
