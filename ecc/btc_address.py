from bitcoinutils.keys import PrivateKey
from bitcoinutils.setup import setup

# Setup de la xarxa
setup('testnet')    # mainnet per real
                    # testnet per proves

def load_private_key(path="ecc/ecc_private_key_wif.txt"):
    
    with open(path, "r") as f:
        wif = f.read().strip()
    return PrivateKey(wif)

def main():

    # Carregar la pk
    private_key = load_private_key()
    public_key = private_key.get_public_key()

    # Generar l'adreça P2WPKH
    address = public_key.get_segwit_address()

    print("Clau Privada (WIF):", private_key.to_wif())
    print("Clau Publica (hex):", public_key.to_hex())
    print("Direccio Bitcoin P2WPKH:", address.to_string())

if __name__ == "__main__":
    main()
