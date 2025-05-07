import hashlib
import os
import binascii
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError

# Fitxers
PK_HEX_FILE = "ecc/ecc_public_key_hex.txt"
SIG_FILE = "signatures/tx_sig_testnet.json"


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
    print("Verificant la signatura...")

    if not os.path.exists(SIG_FILE) or not os.path.exists(PK_HEX_FILE):
        print("Falten fitxers de signatura o clau publica.")
        return

    with open(SIG_FILE, "r") as f:
        signature = f.read().strip()

    with open(PK_HEX_FILE, "r") as f:
        pubkey_hex = f.read().strip()

    dummy_tx_id = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"

    if verify_signature(dummy_tx_id, signature, pubkey_hex):
        print("La signatura es VALIDA.")
    else:
        print("La signatura es INVALIDA.")


if __name__ == "__main__":
    main()
