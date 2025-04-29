import subprocess
import os

def run_script(script_path):
    print(f"Executant {script_path}...")
    result = subprocess.run(["python", script_path], capture_output=True, text=True)
    if result.returncode == 0:
        print(result.stdout)
    else:
        print(f"Error executant {script_path}")
        print(result.stderr)
        exit(1)

def main():
    
    scripts = [
        "lamport/keygen_lamport.py",
        "wots_plus/keygen_wots_plus.py",
        "mss_lots/keygen_mss.py",
        "sphincs/sphincs_temp.py",
        "merkle_ecc/build_merkle_tree.py",
        "ecc/ecc_keys.py",
        "ecc/btc_address.py"
    ]

    for script in scripts:
        if os.path.exists(script):
            run_script(script)
        else:
            print(f"No s'ha trobat el fitxer: {script}")
            exit(1)

    print("Tots els passos completats correctament.")

if __name__ == "__main__":
    main()
