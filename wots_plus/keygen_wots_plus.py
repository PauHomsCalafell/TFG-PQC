import hashlib
import secrets
import json
import math
import os

# Paràmetres globals
W = 16  # Base Winternitz
N = 256  # Ja que utilitzo SHA-256
SEED_SIZE = 32
LOG_W = int(math.log2(W))

# Funció hash
def H(data):
    return hashlib.sha256(data).digest()

# PseudoRandomGenerator per generar claus i màscares
def prg(seed, total):
    return [H(seed + i.to_bytes(4, 'big')) for i in range(total)]

# Funció de cadena amb màscares XOR
def chain_function(x, r_list, steps):
    result = x
    for i in range(steps):
        result = H(bytes(a ^ b for a, b in zip(result, r_list[i]))) # El simbol ^ es la XOR
    return result

# Conversió a base w
def to_base_w(value, digits):
    output = []
    for _ in range(digits):
        output.append(value % W)
        value //= W
    return output[::-1] # Invertida

# Generació de clau WOTS+ a partir d’una sola llavor (llavor secreta i màscares públiques)
def wots_plus_keygen(seed=None):
    if seed is None:
        seed = secrets.token_bytes(SEED_SIZE)

    # Calcular longitud L
    l1 = math.ceil(N / LOG_W)
    l2 = math.ceil(math.log2(l1 * (W - 1)) / LOG_W)
    L = l1 + l2

    # Clau privada: sk = G(seed)
    sk = prg(seed, L)

    # Màscares públiques per cada pas de cada bloc
    r_masks = [[secrets.token_bytes(SEED_SIZE) for _ in range(W - 1)] for _ in range(L)]

    # Clau pública: pk[i] = c_{w-1}(sk[i], r[i])
    pk = [chain_function(sk[i], r_masks[i], W - 1) for i in range(L)]

    return sk, r_masks, pk, L

# Guardar claus a JSON
def save_winternitz_keys(sk, r_masks, pk, sk_file, pk_file):
    with open(sk_file, "w") as f:
        json.dump({
            "sk": [s.hex() for s in sk],
            "r_masks": [[r.hex() for r in rlist] for rlist in r_masks]
        }, f, indent=4)

    pk_hash = H(b''.join(pk))

    with open(pk_file, "w") as f:
        json.dump({
            "pk_hash": pk_hash.hex(),
            "pk": [p.hex() for p in pk]
        }, f, indent=4)


def main():

    os.makedirs("wots_plus", exist_ok=True)

    # Fitxers on es guarden les claus
    SkFile = "wots_plus/sk_Winternitz.json"
    PkFile = "wots_plus/pk_Winternitz.json"

    # Generació
    sk, r_masks, pk, L = wots_plus_keygen()

    # Guardar
    save_winternitz_keys(sk, r_masks, pk, SkFile, PkFile)
    print(f"Claus generades i guardades en {SkFile} i {PkFile}")


if __name__ == "__main__":
    main()
