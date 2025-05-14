from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup

# Setup de la xarxa
setup('testnet')    # mainnet per real
                    # testnet per proves

def load_private_key(path="ecc/ecc_private_key_wif.txt"):
    """
    Carrega una clau privada Bitcoin des d'un fitxer en format WIF (Wallet Import Format).
    Args:
        path (str): Ruta al fitxer que conté la clau privada en format WIF. Per defecte, es carrega 
                    des de "ecc/ecc_private_key_wif.txt".
    Return:
        PrivateKey: La clau privada carregada com a objecte `PrivateKey` de la llibreria `bitcoinutils`.
    """
    
    with open(path, "r") as f:
        wif = f.read().strip()
    return PrivateKey(wif)

def main():
    """
    Genera la clau pública corresponent,
    i crea una adreça Bitcoin SegWit (P2WPKH) per la xarxa testnet.
    """

    # Carregar la pk
    private_key = load_private_key()
    public_key = private_key.get_public_key()

    # Generar l'adreça P2WPKH
    address = public_key.get_segwit_address()

    with open("ecc/btc_address.txt", "w") as f:
        f.write(address.to_string())

    print("Clau Privada (WIF):", private_key.to_wif())
    print("Clau Publica (hex):", public_key.to_hex())
    print("Direccio Bitcoin P2WPKH:", address.to_string())

if __name__ == "__main__":
    main()
