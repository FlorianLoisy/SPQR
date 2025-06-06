#!/usr/bin/env python3
"""
Exemple d'utilisation de SPQR
Ce script montre comment utiliser SPQR programmatiquement
"""

from spqr_cli import SPQRSimple
import json

def main():
    print("=== Exemple d'utilisation SPQR ===")
    
    # Initialiser SPQR
    spqr = SPQRSimple()
    
    # Lister les types d'attaques disponibles
    print("\nTypes d'attaques disponibles:")
    for attack_type in spqr.list_attack_types():
        print(f"  - {attack_type}")
    
    # Effectuer un test rapide
    print("\nTest rapide avec 'web_attack':")
    results = spqr.quick_test("web_attack")
    
    if "error" in results:
        print(f"Erreur: {results['error']}")
    else:
        print("Test réussi!")
        print(f"PCAP: {results.get('pcap_file', 'N/A')}")
        print(f"Logs: {results.get('log_file', 'N/A')}")
        print(f"Rapport: {results.get('report_file', 'N/A')}")

if __name__ == "__main__":
    main()