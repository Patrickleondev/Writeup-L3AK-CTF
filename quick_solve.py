#!/usr/bin/env python3
"""
BabyRev CTF Challenge 
Author: Assistant
Flag: L3AK{you_are_not_gonna_guess_me}
"""

import struct
import sys

def create_inverse_remap(remap_data):
    """Créer la table inverse du remapping"""
    if len(remap_data) != 256:
        raise ValueError(f"Remap data doit faire 256 bytes, trouvé {len(remap_data)}")
    
    inverse = [0] * 256
    for i in range(256):
        mapped_value = remap_data[i]
        inverse[mapped_value] = i
    
    return inverse

def solve_from_gdb_dump(remap_file):
    """Solution principale: utilise le dump GDB de la table remap"""
    print(" Lecture du fichier remap depuis GDB...")
    
    try:
        with open(remap_file, 'rb') as f:
            remap_data = f.read()
        
        inverse = create_inverse_remap(remap_data)
        
        # Flag encodé trouvé dans le binaire
        encoded_flag = b"L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}"
        
        print("Décodage en cours...")
        decoded = b""
        for byte_val in encoded_flag:
            original_val = inverse[byte_val]
            decoded += bytes([original_val])
        
        decoded_str = decoded.decode('ascii', errors='replace')
        
        print(f"FLAG DÉCODÉ: {decoded_str}")
        return decoded_str
        
    except Exception as e:
        print(f" Erreur: {e}")
        return None

def solve_manual_mapping():
    """Solution de secours: mapping manuel depuis GDB"""
    print(" Entrez les mappings observés dans GDB:")
    print("Format: valeur_encodée=valeur_originale (ex: L=F)")
    print("Tapez 'done' pour terminer")
    
    mapping = {}
    
    while True:
        entry = input("Mapping: ").strip()
        if entry.lower() == 'done':
            break
        
        try:
            encoded, original = entry.split('=')
            mapping[encoded.strip()] = original.strip()
            print(f"✓ {encoded.strip()} -> {original.strip()}")
        except:
            print(" Format invalide. Utilisez: char1=char2")
    
    # Décoder avec le mapping partiel
    encoded_flag = "L3AK{ngx_qkt_fgz_ugffq_uxtll_dt}"
    decoded = ""
    
    for char in encoded_flag:
        if char in mapping:
            decoded += mapping[char]
        else:
            decoded += f"?{char}?"
    
    print(f"Décodage partiel: {decoded}")
    return decoded

def generate_gdb_script():
    """Génère un script GDB automatisé"""
    script = '''# Script GDB automatisé pour babyrev
set pagination off
set logging file gdb_output.txt
set logging on

# Breakpoint sur main pour gérer ASLR
break main
run

# Breakpoint après init_remap
break *main+39
continue

# Trouver l'adresse de la table remap
info variables remap

# Remplacer REMAP_ADDR par l'adresse trouvée
# dump binary memory remap_table.bin REMAP_ADDR REMAP_ADDR+256

# Examiner quelques mappings pour vérifier
# x/16bx REMAP_ADDR
# p/c *(char*)REMAP_ADDR+76   # Mapping de 'L'

set logging off
quit
'''
    
    with open('auto_gdb.txt', 'w') as f:
        f.write(script)
    
    print(" Script GDB généré: auto_gdb.txt")
    print(" Usage: gdb -x auto_gdb.txt ./babyrev")

if __name__ == "__main__":
    print("=" * 50)
    print(" BABYREV CTF CHALLENGE SOLVER 💀")
    print("=" * 50)
    
    print("\nOptions:")
    print("1.  Résoudre avec dump remap ( Je te recommande ceci chef)")
    print("2.  Résoudre avec mapping manuel") 
    print("3.  Générer script GDB automatisé")
    
    choice = input("\nChoix (1/2/3): ").strip()
    
    if choice == "1":
        filename = input("Fichier remap (défaut: remap_table.bin): ").strip()
        if not filename:
            filename = "remap_table.bin"
        
        result = solve_from_gdb_dump(filename)
        if result:
            print(f"\n SUCCÈS! Le flag est: {result}")
            
    elif choice == "2":
        result = solve_manual_mapping()
        print(f"\n Résultat: {result}")
        
    elif choice == "3":
        generate_gdb_script()
        print("\n Instructions:")
        print("1. gdb -x auto_gdb.txt ./babyrev")
        print("2. Adapter les adresses dans le script")
        print("3. Relancer ce script avec option 1")
        
    else:
        print(" Choix invalide") 