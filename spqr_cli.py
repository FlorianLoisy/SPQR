#!/usr/bin/env python3
"""
SPQR - Simple Network Rules Testing Tool
Interface en ligne de commande simplifiée
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional
import logging

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SPQRSimple:
    """Interface simplifiée pour SPQR"""
    
    def __init__(self, config_path: str = "config/config.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.setup_directories()
    
    def load_config(self) -> Dict:
        """Charge la configuration ou crée une configuration par défaut"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config non trouvée {self.config_path}, création d'une config par défaut")
            return self.create_default_config()
    
    def create_default_config(self) -> Dict:
        """Crée une configuration par défaut"""
        default_config = {
            "network": {
                "source_ip": "192.168.1.10",
                "dest_ip": "192.168.1.20",
                "source_port": 1234,
                "dest_port": 80
            },
            "suricata": {
                "config_file": "config/suricata.yaml",
                "rules_file": "config/suricata.rules",
                "log_dir": "output/logs"
            },
            "output": {
                "pcap_dir": "output/pcap",
                "reports_dir": "output/reports"
            }
        }
        
        # Sauvegarde la config par défaut
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        return default_config
    
    def setup_directories(self):
        """Crée les répertoires nécessaires"""
        dirs = [
            "input", "output", "output/pcap", "output/reports", 
            "output/logs", "config"
        ]
        for directory in dirs:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def generate_traffic(self, attack_type: str, output_file: str = None) -> str:
        """Génère du trafic réseau pour un type d'attaque"""
        if not output_file:
            output_file = f"output/pcap/{attack_type}_{self.get_timestamp()}.pcap"
        
        logger.info(f"Génération de trafic pour: {attack_type}")
        
        # Import dynamique pour éviter les dépendances si non utilisé
        try:
            from scripts.generate_traffic.spqrlib import generate_pcap
            generate_pcap(attack_type, output_file, self.config)
            logger.info(f"Trafic généré: {output_file}")
            return output_file
        except ImportError:
            logger.error("Module spqrlib non trouvé")
            return None
    
    def test_rules(self, pcap_file: str, rules_file: str = None) -> str:
        """Test les règles Suricata avec un fichier PCAP"""
        if not rules_file:
            rules_file = self.config["suricata"]["rules_file"]
        
        if not os.path.exists(pcap_file):
            logger.error(f"Fichier PCAP non trouvé: {pcap_file}")
            return None
        
        logger.info(f"Test des règles avec: {pcap_file}")
        
        # Commande Suricata
        output_log = f"output/logs/suricata_{self.get_timestamp()}.json"
        cmd = f"suricata -c {self.config['suricata']['config_file']} -S {rules_file} -r {pcap_file} -l output/logs/ --runmode single"
        
        logger.info(f"Exécution: {cmd}")
        
        try:
            import subprocess
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("Test Suricata terminé avec succès")
                return output_log
            else:
                logger.error(f"Erreur Suricata: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution: {e}")
            return None
    
    def generate_report(self, log_file: str) -> str:
        """Génère un rapport à partir des logs Suricata"""
        if not os.path.exists(log_file):
            logger.error(f"Fichier de log non trouvé: {log_file}")
            return None
        
        report_file = f"output/reports/report_{self.get_timestamp()}.txt"
        
        try:
            # Analyse simple des logs
            alerts_count = 0
            unique_sids = set()
            
            with open(log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            log_entry = json.loads(line)
                            if log_entry.get('event_type') == 'alert':
                                alerts_count += 1
                                unique_sids.add(log_entry.get('alert', {}).get('signature_id'))
                        except json.JSONDecodeError:
                            continue
            
            # Génération du rapport
            with open(report_file, 'w') as f:
                f.write(f"=== RAPPORT SPQR ===\n")
                f.write(f"Timestamp: {self.get_timestamp()}\n")
                f.write(f"Fichier analysé: {log_file}\n")
                f.write(f"Nombre total d'alertes: {alerts_count}\n")
                f.write(f"Règles déclenchées: {len(unique_sids)}\n")
                f.write(f"SIDs uniques: {sorted(unique_sids)}\n")
            
            logger.info(f"Rapport généré: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {e}")
            return None
    
    def get_timestamp(self) -> str:
        """Retourne un timestamp formaté"""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def quick_test(self, attack_type: str) -> Dict:
        """Test rapide: génère le trafic, test les règles et génère un rapport"""
        logger.info(f"=== QUICK TEST: {attack_type} ===")
        
        results = {}
        
        # 1. Génération du trafic
        pcap_file = self.generate_traffic(attack_type)
        if not pcap_file:
            return {"error": "Échec de génération du trafic"}
        results["pcap_file"] = pcap_file
        
        # 2. Test des règles
        log_file = self.test_rules(pcap_file)
        if not log_file:
            return {"error": "Échec du test des règles"}
        results["log_file"] = log_file
        
        # 3. Génération du rapport
        report_file = self.generate_report(log_file)
        if not report_file:
            return {"error": "Échec de génération du rapport"}
        results["report_file"] = report_file
        
        logger.info("=== TEST TERMINÉ ===")
        return results
    
    def list_attack_types(self) -> List[str]:
        """Liste les types d'attaques disponibles"""
        # À adapter selon votre implémentation
        return [
            "web_attack", "malware_c2", "data_exfiltration", 
            "port_scan", "brute_force", "dns_tunneling"
        ]


def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(
        description="SPQR - Outil simplifié de test de règles réseau",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python spqr.py quick web_attack           # Test rapide d'attaque web
  python spqr.py generate malware_c2        # Génère seulement du trafic
  python spqr.py test input/malware.pcap    # Test avec un PCAP existant
  python spqr.py report output/logs/eve.json # Génère un rapport
  python spqr.py list                       # Liste les types d'attaques
        """
    )
    
    parser.add_argument(
        'action', 
        choices=['quick', 'generate', 'test', 'report', 'list'],
        help='Action à effectuer'
    )
    
    parser.add_argument(
        'target', 
        nargs='?',
        help='Type d\'attaque, fichier PCAP ou fichier de log selon l\'action'
    )
    
    parser.add_argument(
        '--config', 
        default='config/config.json',
        help='Fichier de configuration (défaut: config/config.json)'
    )
    
    parser.add_argument(
        '--output', 
        help='Fichier de sortie personnalisé'
    )
    
    parser.add_argument(
        '--rules', 
        help='Fichier de règles personnalisé'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mode verbeux'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialisation de SPQR
    spqr = SPQRSimple(args.config)
    
    try:
        if args.action == 'list':
            print("Types d'attaques disponibles:")
            for attack_type in spqr.list_attack_types():
                print(f"  - {attack_type}")
        
        elif args.action == 'quick':
            if not args.target:
                print("Erreur: Spécifiez le type d'attaque")
                sys.exit(1)
            
            results = spqr.quick_test(args.target)
            if "error" in results:
                print(f"Erreur: {results['error']}")
                sys.exit(1)
            
            print("=== RÉSULTATS ===")
            print(f"PCAP généré: {results['pcap_file']}")
            print(f"Logs: {results['log_file']}")
            print(f"Rapport: {results['report_file']}")
        
        elif args.action == 'generate':
            if not args.target:
                print("Erreur: Spécifiez le type d'attaque")
                sys.exit(1)
            
            pcap_file = spqr.generate_traffic(args.target, args.output)
            if pcap_file:
                print(f"Trafic généré: {pcap_file}")
            else:
                print("Échec de génération du trafic")
                sys.exit(1)
        
        elif args.action == 'test':
            if not args.target:
                print("Erreur: Spécifiez le fichier PCAP")
                sys.exit(1)
            
            log_file = spqr.test_rules(args.target, args.rules)
            if log_file:
                print(f"Test terminé, logs: {log_file}")
            else:
                print("Échec du test")
                sys.exit(1)
        
        elif args.action == 'report':
            if not args.target:
                print("Erreur: Spécifiez le fichier de log")
                sys.exit(1)
            
            report_file = spqr.generate_report(args.target)
            if report_file:
                print(f"Rapport généré: {report_file}")
            else:
                print("Échec de génération du rapport")
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nInterruption par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erreur inattendue: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
