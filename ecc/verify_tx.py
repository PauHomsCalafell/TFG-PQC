import json
import os
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import hashlib


# Sintaxi de tipus type hints per facilitar debug
def verify_signature(tx_id: str, signature_hex: str, pubkey_hex: str) -> bool:
    try:
        tx_bytes = bytes.fromhex(tx_id)
        signature_bytes = bytes.fromhex(signature_hex)
        pubkey_bytes = bytes.fromhex(pubkey_hex)

        # Carreguem la clau pública no comprimida (65 bytes)
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)

        return vk.verify(signature_bytes, tx_bytes, hashfunc=hashlib.sha256)

    except BadSignatureError:
        print("Signatura incorrecta: no coincideix amb el missatge i la clau pública.")
        return False
    except Exception as e:
        print(f"Error inesperat: {str(e)}")
        return False

def main():

    sig_file = "signatures/tx_sig.json"

    print("Verificant la signatura...")

    if not os.path.exists(sig_file):
        print(f"No s'ha trobat el fitxer de signatura: {sig_file}")
        return

    with open(sig_file, "r") as f:
        data = json.load(f)
        tx_id = data["tx_id"]
        signature = data["signature"]
        pubkey_hex = data["public_key"]

    if not tx_id or not signature or not pubkey_hex:
        print("El fitxer de signatura està incomplet.")
        return

    valid = verify_signature(tx_id, signature, pubkey_hex)

    if valid:
        print("La signatura es VALIDA.")
    else:
        print("La signatura es INVALIDA.")

if __name__ == "__main__":
    main()
