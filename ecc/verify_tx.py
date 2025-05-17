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
    Es filtra per `tx_id` per identificar la signatura verificar.
    """

    sig_file = "signatures/tx_sig.json"

    # Tx_is que volem verificar
    tx_id_to_verify = "746231713672733767656c657a6d366136336735783934326675676d706168636c3678726674796c636b"

    # Carrega les dades del fitxer JSON
    with open(sig_file, "r") as f:
        data = json.load(f)
        
        # Buscar el tx_id dins de les signatures
        for signature_data in data["signatures"]:
            tx_id = signature_data["tx_id"]
            if tx_id == tx_id_to_verify:
                signature = signature_data["signature"]
                pubkey_hex = signature_data["public_key"]

                # Verifica
                valid = verify_signature(tx_id, signature, pubkey_hex)

                if valid:
                    print(f"La signatura per la transaccio {tx_id} es valida.")
                else:
                    print(f"La signatura per la transaccio {tx_id} NO es valida.")
                break
        else:
            print(f"El `tx_id` {tx_id_to_verify} no es troba al fitxer de signatures.")

if __name__ == "__main__":
    main()
