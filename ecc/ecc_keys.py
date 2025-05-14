import os
import json
import hashlib
from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup
import base58

# Setup de xarxa
setup('testnet')    # mainnet per real
                    # testnet per proves

def load_merkle_root(path="merkle_ecc/root_merkle.json"):
    """
    Carrega l'arrel de l'arbre de Merkle des d'un fitxer JSON.
    Args:
        path (str): Ruta al fitxer JSON on es guarda l'arrel de l'arbre de Merkle.
    Return:
        bytes: L'arrel de l'arbre de Merkle com un valor en bytes.
    """
    
    with open(path, "r") as f:
        data = json.load(f)
    return bytes.fromhex(data["merkle_root"])

def generate_private_key_from_merkle_root(root):
    """
    Deriva una clau privada Bitcoin a partir del root utilitzant SHA-256.
    Args:
        root (bytes): L'arrel de l'arbre de Merkle que es fa servir com a entrada per generar la clau privada.
    Return:
        PrivateKey: La clau privada Bitcoin generada.
    """

    sk_hash = hashlib.sha256(root).digest()
    
    # Versió 0x80 per mainnet
    # Versió 0xEF per testnet
    version_byte = b'\xEF'

    payload = version_byte + sk_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    wif = base58.b58encode(payload + checksum).decode()

    return PrivateKey(wif)

# Guarda les claus
def save_keys_to_files(private_key):
    """
    Guarda les claus pública i privada en arxius.
    Args:
        private_key (PrivateKey): La clau privada Bitcoin generada per guardar en un arxiu.
    """

    os.makedirs("ecc", exist_ok=True)

    with open("ecc/ecc_private_key_wif.txt", "w") as f:
        f.write(private_key.to_wif())

    public_key = private_key.get_public_key()
    with open("ecc/ecc_public_key_hex.txt", "w") as f:
        f.write(public_key.to_hex())

def main():
    """
    Genera la clau privada i pública 
    Bitcoin a partir d'aquesta arrel i les guarda en fitxers.
    """
    
    merkle_root = load_merkle_root()
    private_key = generate_private_key_from_merkle_root(merkle_root)
    save_keys_to_files(private_key)

    print("Clau privada i publica ECC Bitcoin generades i guardades correctament.")

if __name__ == "__main__":
    main()
