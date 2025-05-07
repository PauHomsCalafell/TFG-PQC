import hashlib
import os
import json
import binascii
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError


def decompress_pubkey(pubkey_bytes):
    """
    Converteix una public key comprimida (33 bytes) a format no comprimit (65 bytes)
    """
    from ecdsa.ellipticcurve import CurveFp, Point
    from ecdsa.curves import SECP256k1

    p = SECP256k1.curve.p()
    a = SECP256k1.curve.a()
    b = SECP256k1.curve.b()
    curve = CurveFp(p, a, b)

    prefix = pubkey_bytes[0]
    x = int.from_bytes(pubkey_bytes[1:], 'big')

    # y^2 = x^3 + ax + b
    y_squared = (x**3 + a * x + b) % p
    y = pow(y_squared, (p + 1) // 4, p)

    if (prefix == 0x02 and y % 2 != 0) or (prefix == 0x03 and y % 2 == 0):
        y = (-y) % p

    point = Point(curve, x, y)
    vk = VerifyingKey.from_public_point(point, curve=SECP256k1)
    return vk


def verify_signature(tx_id, signature_hex, pubkey_hex):
    tx_id_bytes = tx_id.encode()
    sig_bytes = bytes.fromhex(signature_hex)
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    try:
        vk = decompress_pubkey(pubkey_bytes)
        is_valid = vk.verify(sig_bytes, tx_id_bytes)
        return is_valid
    except (BadSignatureError, Exception) as e:
        print("Error durant la verificacio:", str(e))
        return False


def main():

    pk_hex_file = "ecc/ecc_public_key_hex.txt"
    sig_file = "signatures/tx_sig.json"


    print("Verificant la signatura...")

    if not os.path.exists(sig_file) or not os.path.exists(pk_hex_file):
        print("Falten fitxers de signatura o clau publica.")
        return

    with open(sig_file, "r") as f:
        data = json.load(f)
        dummy_tx_id = data["tx_id"]
        signature = data["signature"]
        public_key = data["public_key"]

    if verify_signature(dummy_tx_id, signature, public_key):
        print("La signatura es VALIDA.")
    else:
        print("La signatura es INVALIDA.")


if __name__ == "__main__":
    main()
