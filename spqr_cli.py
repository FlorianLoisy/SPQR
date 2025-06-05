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

from spqrlib import generate_pcap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SPQR")

class SPQRSimple:
    def __init__(self, config_file="config/config.json"):
        with open(config_file, "r") as f:
            self.config = json.load(f)

    def list_attack_types(self) -> List[str]:
        return list(self.config.get("traffic_patterns", {}).keys())

    def get_timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def quick_test(self, attack_type: str) -> Dict:
        timestamp = self.get_timestamp()
        pcap_filename = f"{attack_type}_{timestamp}.pcap"
        pcap_path = os.path.join(self.config["output"]["pcap_dir"], pcap_filename)

        try:
            generate_pcap(attack_type, pcap_path, self.config)
        except Exception as e:
            return {"error": str(e)}

        log_file = self.test_rules(pcap_path)
        if not log_file:
            return {"error": "Test échoué"}

        report_file = self.generate_report(log_file)

        return {
            "pcap_file": pcap_path,
            "log_file": log_file,
            "report_file": report_file
        }

    def test_rules(self, pcap_file: str, rules_file: str = None) -> str:
        engine = self.config.get("engine", {})
        engine_type = engine.get("type", "suricata")
        version = engine.get("version", "6.0.15")
        mode = engine.get("mode", "docker")

        log_dir = Path(self.config["suricata"]["log_dir"]).absolute()
        config_path = Path(self.config["suricata"]["config_file"]).absolute()
        rules_path = Path(rules_file or self.config["suricata"]["rules_file"]).absolute()
        pcap_path = Path(pcap_file).absolute()

        os.makedirs(log_dir, exist_ok=True)

        if mode == "docker":
            image = f"spqr/{engine_type}:{version}"
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{pcap_path}:/input.pcap:ro",
                "-v", f"{config_path}:/etc/suricata/suricata.yaml:ro",
                "-v", f"{rules_path}:/etc/suricata/suricata.rules:ro",
                "-v", f"{log_dir}:/var/log/suricata",
                image,
                "-c", "/etc/suricata/suricata.yaml",
                "-S", "/etc/suricata/suricata.rules",
                "-r", "/input.pcap",
                "-l", "/var/log/suricata"
            ]
        else:
            cmd = [
                "suricata",
                "-c", str(config_path),
                "-S", str(rules_path),
                "-r", str(pcap_path),
                "-l", str(log_dir)
            ]

        try:
            subprocess.run(cmd, check=True)
            return str(log_dir / "eve.json")
        except subprocess.CalledProcessError as e:
            logger.error(f"Erreur d'exécution : {e}")
            return None

    def generate_report(self, log_file: str) -> str:
        report_dir = Path(self.config["output"]["reports_dir"])
        os.makedirs(report_dir, exist_ok=True)
        timestamp = self.get_timestamp()
        report_path = report_dir / f"report_{timestamp}.txt"

        alerts_count = 0
        unique_sids = set()

        try:
            with open(log_file, "r") as f:
                for line in f:
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            if entry.get("event_type") == "alert":
                                alerts_count += 1
                                sid = entry.get("alert", {}).get("signature_id")
                                if sid:
                                    unique_sids.add(sid)
                        except json.JSONDecodeError:
                            continue

            with open(report_path, "w") as rpt:
                rpt.write(f"=== RAPPORT SPQR ===\n")
                rpt.write(f"Timestamp: {timestamp}\n")
                rpt.write(f"Fichier de log: {log_file}\n")
                rpt.write(f"Nombre total d'alertes: {alerts_count}\n")
                rpt.write(f"SIDs uniques: {sorted(unique_sids)}\n")

            return str(report_path)
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport : {e}")
            return None

    def test_all_engines(self, pcap_file: str) -> Dict:
        results = {}
        engines = self.config.get("engines", [])

        for engine in engines:
            engine_name = f"{engine['type']}_{engine['version']}"
            logger.info(f"⏳ Test avec {engine_name}")

            log_dir_backup = self.config["suricata"]["log_dir"]
            report_dir_backup = self.config["output"]["reports_dir"]

            self.config["suricata"]["log_dir"] = f"output/logs/{engine_name}"
            self.config["output"]["reports_dir"] = f"output/reports/{engine_name}"
            Path(self.config["suricata"]["log_dir"]).mkdir(parents=True, exist_ok=True)
            Path(self.config["output"]["reports_dir"]).mkdir(parents=True, exist_ok=True)

            self.config["engine"] = engine

            log_file = self.test_rules(pcap_file)
            if not log_file:
                results[engine_name] = {"error": "Échec du test"}
                continue

            report_file = self.generate_report(log_file)
            results[engine_name] = {
                "log_file": log_file,
                "report_file": report_file
            }

            self.config["suricata"]["log_dir"] = log_dir_backup
            self.config["output"]["reports_dir"] = report_dir_backup

        return results


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