#!/usr/bin/env python3
"""
SPQR - Simple Network Rules Testing Tool
Interface en ligne de commande simplifiée
"""

import argparse
import json
import sys
import os
import subprocess
from pathlib import Path
from datetime import datetime
import logging
from typing import Dict, List

from scripts.generate_traffic.spqrlib import (
    PcapGenerator, FlowGenerator, generate_pcap
)  # Assurez-vous que le nom du fichier est correct
from scripts.generate_path.folder import FolderGenerator
from scripts.process.process import (SuricataExecution, SnortExecution, SPQRSimple)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SPQR")



def main():
    parser = argparse.ArgumentParser(description="SPQR CLI")
    parser.add_argument("action", choices=["quick", "generate", "test", "report", "list", "test-all"], help="Action à effectuer")
    parser.add_argument("target", nargs="?", help="Type d'attaque, fichier PCAP ou fichier de log")
    parser.add_argument("--rules", help="Fichier de règles personnalisé")
    parser.add_argument("--config", default="config/config.json", help="Chemin vers le fichier de configuration")
    parser.add_argument("--output", help="Fichier de sortie personnalisé (pour generate)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Affiche les logs détaillés")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    spqr = SPQRSimple(config_file=args.config)

    if args.action == "list":
        print("Types d'attaques disponibles :")
        for attack_type in spqr.list_attack_types():
            print(f"  - {attack_type}")

    elif args.action == "quick":
        if not args.target:
            print("Erreur : spécifiez un type d'attaque")
            return
        results = spqr.quick_test(args.target)
        print(json.dumps(results, indent=2))

    elif args.action == "generate":
        if not args.target:
            print("Erreur : spécifiez un type d'attaque")
            return
        output_file = args.output or f"output/pcap/{args.target}_{spqr.get_timestamp()}.pcap"
        try:
            generate_pcap(args.target, output_file, spqr.config)
            print(f"PCAP généré : {output_file}")
        except Exception as e:
            print(f"Erreur : {e}")

    elif args.action == "test":
        if not args.target:
            print("Erreur : spécifiez un fichier PCAP")
            return
        log_file = spqr.test_rules(args.target, args.rules)
        print(f"Log généré : {log_file}")

    elif args.action == "report":
        if not args.target:
            print("Erreur : spécifiez un fichier de log")
            return
        report_file = spqr.generate_report(args.target)
        print(f"Rapport généré : {report_file}")

    elif args.action == "test-all":
        if not args.target:
            print("Erreur : spécifiez un fichier PCAP")
            return
        results = spqr.test_all_engines(args.target)
        print("=== RÉSULTATS MULTI-IDS ===")
        for engine, res in results.items():
            print(f"\n--- {engine} ---")
            if "error" in res:
                print(f"Erreur : {res['error']}")
            else:
                print(f"Log : {res['log_file']}")
                print(f"Rapport : {res['report_file']}")

if __name__ == "__main__":
    main()