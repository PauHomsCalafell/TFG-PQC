import os
import json
import hashlib

# Funció hash
def H(data):
    return hashlib.sha256(data).digest()

# Llegeix el pk_hash des d’un fitxer JSON
def load_pk_hash(path):
    with open(path, "r") as f:
        data = json.load(f)
    return bytes.fromhex(data["pk_hash"])

# Construeix l’arbre de Merkle
def build_merkle_tree(leaves):
    tree = [leaves[:]]  # Nivell 0: fulles
    while len(tree[-1]) > 1:
        prev_level = tree[-1]
        new_level = []
        for i in range(0, len(prev_level), 2):
            left = prev_level[i]
            right = prev_level[i + 1]
            parent = H(left + right) # Concatenació
            new_level.append(parent)
        tree.append(new_level)
    return tree

# Obté el camí d'autenticació per una fulla concreta
def get_auth_path(tree, index):
    path = []
    for level in tree[:-1]:
        sibling_index = index ^ 1  # XOR per trobar el germà
        path.append(level[sibling_index])
        index //= 2
    return path

# Guarda l’arrel, fulles i auth_paths
def save_merkle_data(scheme_names, leaves, tree, path="merkle_ecc/root_merkle.json"):
    
    root = tree[-1][0]

    auth_paths = {
        scheme_names[i]: [sibling.hex() for sibling in get_auth_path(tree, i)]
        for i in range(len(leaves))
    }

    with open(path, "w") as f:
        json.dump({
            "merkle_root": root.hex(),
            "leaves": [leaf.hex() for leaf in leaves],
            "auth_paths": auth_paths
        }, f, indent=4)

def main():
    
    os.makedirs("merkle_ecc", exist_ok=True)
    
    # Diccionari amb nom d'esquema i ruta del fitxer
    schemes = {
        "lamport": "lamport/pk_Lamport.json",
        "wots_plus": "wots_plus/pk_Winternitz.json",
        "mss_lots": "mss_lots/pk_MSS.json",
        "sphincs": "sphincs/pk_SPHINCS.json"
    }

    # Carrega els pk_hash de cada esquema
    leaves = []
    scheme_names = []

    for name, path in schemes.items():
        pk_hash = load_pk_hash(path)
        leaves.append(pk_hash)
        scheme_names.append(name)

    # Construeix arbre Merkle
    tree = build_merkle_tree(leaves)

    # Guarda arrel i auth_paths
    save_merkle_data(scheme_names, leaves, tree)

    print("Arbre Merkle creat i desat.")
    print("Arrel:", tree[-1][0].hex())

if __name__ == "__main__":
    main()
