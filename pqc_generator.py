"""
Generador central del projecte TFG-PQC.
Executa de forma ordenada els passos següents:
 1. Generació de claus HBS (Lamport, WOTS+, MSS, SPHINCS)
 2. Construcció de l'arbre de Merkle a partir de les pk
 3. Derivació de la clau privada ECC des del root
 4. Generació de la public key ECC i adreça Bitcoin
"""

from lamport.keygen_lamport import main as generate_lamport_keys
from wots_plus.keygen_wots_plus import main as generate_wots_keys
from mss_lots.keygen_mss import main as generate_mss_keys
from sphincs.sphincs_temp import main as generate_temp_sphincs_keys
from sphincs.keygen_sphincs import main as generate_sphincs_keys
from merkle_ecc.build_merkle_tree import main as build_merkle_tree
from ecc.ecc_keys import main as generate_ecc_keys_from_merkle_root
from ecc.btc_address import main as generate_btc_address


def main():
    """
    Funció principal que coordina la generació de tots els components del sistema.
    No rep paràmetres. No retorna res.
    Les funcions que executa escriuen les seves sortides en fitxers .json o .txt
    segons el cas.
    """

    # 1. Generació de claus per a cada esquema HBS
    generate_lamport_keys()
    generate_wots_keys()
    generate_mss_keys()
    #generate_temp_sphincs_keys() #Nomes si s'utilitza windows
    generate_sphincs_keys()
    print()

    # 2. Construcció de l'arbre de Merkle i obtenció de l'arrel
    build_merkle_tree()
    print()

    # 3. Derivació de la clau privada ECC i guardat
    generate_ecc_keys_from_merkle_root()
    print()
    
    # 4. Generació de l'adreça Bitcoin i guardat
    generate_btc_address()

if __name__ == "__main__":
    main()
