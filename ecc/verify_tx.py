import json
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
import hashlib


def verify_signature(tx_id, signature_hex, pubkey_hex):
    """
    Verifica la signatura d'una transacció utilitzant la clau pública corresponent.
    Args:
        tx_id (str): L'ID de la transacció en format hexadecimal.
        signature_hex (str): La signatura de la transacció en format hexadecimal.
        pubkey_hex (str): La clau pública en format hexadecimal.
    Return:
        bool: Retorna True si la signatura és vàlida, False si no ho és.
    """

    try:
        tx_bytes = bytes.fromhex(tx_id)
        signature_bytes = bytes.fromhex(signature_hex)
        pubkey_bytes = bytes.fromhex(pubkey_hex)

        # Carreguem la clau pública no comprimida (65 bytes)
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)

        return vk.verify(signature_bytes, tx_bytes, hashfunc=hashlib.sha256)

    except BadSignatureError:
        print("Signatura incorrecta: no coincideix amb el missatge i la clau publica.")
        return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

def main():
    """
    Funció principal que carrega una signatura des d'un fitxer JSON i verifica la seva validesa.
    """

    sig_file = "signatures/tx_sig.json"

    with open(sig_file, "r") as f:
        data = json.load(f)
        tx_id = data["tx_id"]
        signature = data["signature"]
        pubkey_hex = data["public_key"]

    valid = verify_signature(tx_id, signature, pubkey_hex)

    if valid:
        print("La signatura es VALIDA.")
    else:
        print("La signatura es INVALIDA.")

if __name__ == "__main__":
    main()
