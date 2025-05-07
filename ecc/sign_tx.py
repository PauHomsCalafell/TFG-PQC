import os
import json
import hashlib
from ecdsa import SigningKey, SECP256k1
from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup

setup("testnet")    # mainnet per real
                    # testnet per proves


def load_private_key(path):
    with open(path, "r") as f:
        wif = f.read().strip()
    return PrivateKey(wif)


def sign_tx_id(tx_id_hex, priv):
    sk_bytes = priv.to_bytes()  # Extreu els bytes de la sk
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    tx_bytes = bytes.fromhex(tx_id_hex)
    signature = sk.sign_deterministic(tx_bytes, hashfunc=hashlib.sha256)
    return signature.hex()


def save_signature(tx_id, signature, public_key_hex, filename):
    data = {
        "tx_id": tx_id,
        "signature": signature,
        "public_key": public_key_hex
    }

    os.makedirs(os.path.dirname(filename), exist_ok=True)

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Signatura guardada a: {filename}")

def main():

    sk_filename = "ecc/ecc_private_key_wif.txt"
    signature_out_file = "signatures/tx_sig.json"

    # tx_id de 32 bytes inventat
    dummy_tx_id = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"

    sk = load_private_key(sk_filename)
    pk = sk.get_public_key().to_hex()

    signature = sign_tx_id(dummy_tx_id, sk)
    print("Signatura generada:", signature)

    save_signature(dummy_tx_id, signature, pk, signature_out_file)

if __name__ == "__main__":
    main()
