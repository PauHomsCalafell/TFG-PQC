# Digests as Secret Keys (DASK) for PQC solutions

Aquest projecte implementa una arquitectura post-quàntica utilitzant esquemes de signatures basats en hash (HBS) i criptografia clàssica ECC per generar una adreça Bitcoin segura contra atacs quàntics.

## Estructura general

Cada esquema de signatura es troba encapsulat en el seu propi mòdul i es pot executar independentment. El script `pqc_generator.py` executa tots els procesos.

---

## Esquemes de Signatura Basats en Hash (HBS)

### `lamport/keygen_lamport.py`

- **`lamport_keygen()`**: Genera 256 claus privades dobles i les corresponents claus públiques.
- **`save_lamport_key()`**: Desa les claus en fitxers `.json`.
- **`main()`**: Crida a les anteriors funcions i desa les claus a la carpeta `lamport/`.

### `wots_plus/keygen_wots_plus.py`

- **`wots_plus_keygen()`**: Implementa WOTS+ amb funció de cadena i màscares XOR. Genera claus privades, màscares i claus públiques.
- **`save_winternitz_keys()`**: Desa les claus a `.json`.
- **`main()`**: Controla el procés i desa els fitxers a `wots_plus/`.

### `mss_lots/keygen_mss.py`

- **`mss_keygen()`**: Genera diverses claus Lamport i construeix un arbre de Merkle amb elles.
- **`mss_sign()`**: Signa un missatge utilitzant un dels fulls de l'arbre i la seva auth_path.
- **`mss_verify()`**: Verifica una signatura amb Lamport + Merkle.
- **`save_mss_keys()` / `load_mss_keys()`**: Guarda i recupera les claus del disc.
- **`main()`**: Crida a la generació i desa les claus dins `mss_lots/`.

### `sphincs/keygen_sphincs.py` (actualment `sphincs_temp.py`)

- **`generate_sphincs_keypair()`**: Genera claus públiques i privades falses (per simulació).
- **`save_sphincs_keys()`**: Desa les claus en fitxers `.json`.
- **`main()`**: Desa fitxers dins `sphincs/`.

---

## Arbre de Merkle i Criptografia Clàssica

### `merkle_ecc/build_merkle_tree.py`

- **`build_merkle_tree_from_files()`**: Llegeix totes les claus públiques dels esquemes HBS i construeix un arbre de Merkle. Desa l’arrel i auth_paths.

### `ecc/ecc_keys.py`

- **`generate_ecc_keys_from_merkle_root()`**: Deriva una clau privada ECC aplicant SHA-256 a l’arrel de Merkle. Desa les claus en format WIF i hex.

### `ecc/btc_address.py`

- **`generate_btc_address()`**: Genera una adreça Bitcoin Bech32 (P2WPKH) a partir de la clau pública ECC.

---

## Generador Central

### `pqc_generator.py`

- **`main()`**: Executa en ordre:
  1. Generació de claus HBS
  2. Construcció arbre Merkle
  3. Derivació clau ECC
  4. Generació adreça Bitcoin

---

## Requisits

- Python 3.8+
- Llibreries estàndard (hashlib, secrets, json, os)

---

## Estat actual

- [x] Lamport OTS funcional
- [x] WOTS+ funcional
- [x] MSS amb arbre de Merkle
- [x] Simulació SPHINCS+
- [x] Derivació clau ECC i adreça Bitcoin
- [x] Signatura i verificació d’una transacció dummy

---

## Autor

TFG – Grau en Enginyeria Informàtica, Universitat Autònoma de Barcelona  
Tema: Digests as Secret Keys (DASK) for PQC solutions
