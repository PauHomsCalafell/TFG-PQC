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
    with open(path, "r") as f:
        data = json.load(f)
    return bytes.fromhex(data["merkle_root"])

# Deriva una clau privada Bitcoin a partir del root
def generate_private_key_from_merkle_root(root):
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
    os.makedirs("ecc", exist_ok=True)

    with open("ecc/ecc_private_key_wif.txt", "w") as f:
        f.write(private_key.to_wif())

    public_key = private_key.get_public_key()
    with open("ecc/ecc_public_key_hex.txt", "w") as f:
        f.write(public_key.to_hex())

def main():
    
    merkle_root = load_merkle_root()
    private_key = generate_private_key_from_merkle_root(merkle_root)
    save_keys_to_files(private_key)

    print("Clau privada i publica Bitcoin generades i guardades correctament.")

if __name__ == "__main__":
    main()
