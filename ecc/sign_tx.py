import os
import json
import hashlib
from ecdsa import SigningKey, SECP256k1
from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup

setup("testnet")    # mainnet per real
                    # testnet per proves


def load_private_key(path):
    """
    Carrega la clau privada Bitcoin en format WIF des d'un fitxer.
    Args:
        path (str): Ruta al fitxer que conté la clau privada en format WIF.
    Return:
        PrivateKey: L'objecte `PrivateKey` que conté la clau privada.
    """
    
    with open(path, "r") as f:
        wif = f.read().strip()
    return PrivateKey(wif)


def load_tx_id(path):
    """
    Carrega l'ID de la transacció des d'un fitxer.
    Args:
        path (str): Ruta al fitxer que conté l'ID de la transacció.
    Return:
        str: L'ID de la transacció com a cadena hexadecimal.
    """

    with open(path, "r") as f:
        tx_id = f.read().strip()
    return tx_id


def sign_tx_id(tx_id_hex, priv):
    """
    Signa l'ID d'una transacció amb la clau privada utilitzant ECDSA amb la corba SECP256k1.
    Args:
        tx_id_hex (str): L'ID de la transacció en format hexadecimal.
        priv (PrivateKey): La clau privada per signar l'ID de la transacció.
    Return:
        str: La signatura generada per la transacció.
    """

    sk_bytes = priv.to_bytes()  # Extreu els bytes de la sk
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    tx_bytes = bytes.fromhex(tx_id_hex)
    signature = sk.sign_deterministic(tx_bytes, hashfunc=hashlib.sha256)
    return signature.hex()


def save_signature(tx_id, signature, pk_hex, signature_out_file):
    """
    Guarda les signatures de transaccions en un fitxer JSON, afegint noves signatures sense sobrescriure les anteriors.
    Args:
        tx_id (str): L'ID de la transacció signada.
        signature (str): La signatura de la transacció.
        pk_hex (str): La clau pública en format hexadecimal.
        signature_out_file (str): Ruta on es guarda el fitxer de sortida.
    """

    # Comprovació si el fitxer ja existeix
    if os.path.exists(signature_out_file):
        with open(signature_out_file, "r") as f:
            data = json.load(f)
    else:
        # Si no existeix, inicialitzar la llista
        data = {"signatures": []}

    data["signatures"].append({
        "tx_id": tx_id,
        "signature": signature,
        "public_key": pk_hex
    })

    os.makedirs(os.path.dirname(signature_out_file), exist_ok=True)

    with open(signature_out_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Signatura guardada a: {signature_out_file}")

def main():
    """
    Funció principal que carrega la clau privada, l'ID de la transacció, signa la transacció 
    i gaurda la signatura i les dades en un fitxer.
    """

    sk_filename = "ecc/ecc_private_key_wif.txt"
    tx_id_filename = "ecc/btc_address.txt"
    signature_out_file = "signatures/tx_sig.json"

    tx_id = load_tx_id(tx_id_filename).encode().hex()
    sk = load_private_key(sk_filename)
    pk_hex = sk.get_public_key().to_hex(compressed=False)

    signature = sign_tx_id(tx_id, sk)
    print("Signatura generada:", signature)

    save_signature(tx_id, signature, pk_hex, signature_out_file)

if __name__ == "__main__":
    main()
