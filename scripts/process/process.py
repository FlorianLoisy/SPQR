import os
import datetime
import pathlib
import json
import subprocess
from pathlib import Path
from datetime import datetime
import logging
from typing import Dict, List

from scripts.generate_traffic.spqrlib import (
    PcapGenerator, FlowGenerator, generate_pcap
)  # Assurez-vous que le nom du fichier est correct
from scripts.generate_path.folder import FolderGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SPQR")

'''
Ce fichier a été créé dans le but de réaliser les tâches dédiées aux processus de création de règle.
'''

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

        # Convert paths to absolute and verify files exist
        log_dir = Path(self.config["suricata"]["log_dir"]).absolute()
        config_path = Path(self.config["suricata"]["config_file"]).absolute()
        rules_path = Path(rules_file or self.config["suricata"]["rules_file"]).absolute()
        pcap_path = Path(pcap_file).absolute()

        # Verify files exist
        if not pcap_path.is_file():
            logger.error(f"PCAP file not found: {pcap_path}")
            return None
        if not config_path.is_file():
            logger.error(f"Config file not found: {config_path}")
            return None
        if not rules_path.is_file():
            logger.error(f"Rules file not found: {rules_path}")
            return None

        # Create log directory
        os.makedirs(log_dir, exist_ok=True)

        if mode == "docker":
            # Ensure config directory structure exists in container
            container_config_dir = "/etc/suricata"
            container_rules_dir = f"{container_config_dir}/rules"
            
            # Use consistent paths inside container
            image = f"spqr_{engine_type}_{version}"
            cmd = [
                "docker", "run", "--rm",
                # Create required directories in container
                "--entrypoint", "sh",
                image,
                "-c", f"mkdir -p {container_rules_dir} && suricata "
                f"-c {container_config_dir}/suricata.yaml "
                f"-S {container_rules_dir}/suricata.rules "
                f"-r /input.pcap "
                f"-l /var/log/suricata",
                # Mount volumes
                "-v", f"{pcap_path}:/input.pcap:ro",
                "-v", f"{config_path}:{container_config_dir}/suricata.yaml:ro",
                "-v", f"{rules_path}:{container_rules_dir}/suricata.rules:ro",
                "-v", f"{log_dir}:/var/log/suricata"
            ]

            # Log the command for debugging
            logger.info(f"Config file path: {config_path}")
            logger.info(f"Rules file path: {rules_path}")
            logger.debug(f"Executing command: {' '.join(cmd)}")
            
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                logger.debug(f"Command output: {result.stdout}")
                return str(log_dir / "eve.json")
            except subprocess.CalledProcessError as e:
                logger.error(f"Command failed with output:\n{e.stdout}\n{e.stderr}")
                return None
        else:
            cmd = [
                "suricata",
                "-c", str(config_path),
                "-S", str(rules_path),
                "-r", str(pcap_path),
                "-l", str(log_dir)
            ]
            return subprocess.run(cmd, check=True)

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

    def process_pcap(self, pcap_path, config_path, rules_path, log_dir, mode="docker", version="6.0.15"):
        # Convert relative paths to absolute
        pcap_path = os.path.abspath(pcap_path)
        config_path = os.path.abspath(config_path)
        rules_path = os.path.abspath(rules_path)
        log_dir = os.path.abspath(log_dir)

        if mode == "docker":
            image = f"spqr_suricata_{version}"
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{pcap_path}:/input.pcap:ro",
                "-v", f"{config_path}:/etc/suricata/suricata.yaml:ro",
                "-v", f"{rules_path}:/etc/suricata/suricata.rules:ro",
                "-v", f"{log_dir}:/var/log/suricata",
                image,
                "suricata",
                "-c", "/etc/suricata/suricata.yaml",
                "-S", "/etc/suricata/suricata.rules",
                "-r", "/input.pcap",
                "-l", "/var/log/suricata"
            ]
            # Add debug output
            print(f"Executing command: {' '.join(cmd)}")
            return subprocess.run(cmd, check=True)
        else:
            cmd = [
                "suricata",
                "-c", str(config_path),
                "-S", str(rules_path),
                "-r", str(pcap_path),
                "-l", str(log_dir)
            ]
            return subprocess.run(cmd, check=True)

    def generate_pcap(self, attack_type: str) -> Dict:
        """Generate PCAP file only"""
        try:
            pcap_path = self._generate_attack_pcap(attack_type)
            return {"pcap_file": pcap_path}
        except Exception as e:
            return {"error": str(e)}

    def test_with_engine(self, pcap_file: str, engine_type: str, version: str) -> Dict:
        """Test PCAP with specific engine"""
        try:
            engine_config = {
                "type": engine_type,
                "version": version,
                "mode": "docker"
            }
            self.config["engine"] = engine_config
            
            log_file = self.test_rules(pcap_file)
            if not log_file:
                return {"error": "Test failed"}

            # Count alerts
            alert_count = 0
            if os.path.exists(log_file):
                with open(log_file) as f:
                    alert_count = sum(1 for line in f if '"event_type":"alert"' in line)

            return {
                "log_file": log_file,
                "alert_count": alert_count
            }
        except Exception as e:
            return {"error": str(e)}

class SuricataExecution:
    def __init__(self):
        """
        Initialise une instance de SuricataExecution.

        Parameters:

        """        
    def suricata_execution(self, process, result_path, pcap_path, nom_dossier, file_pcap_name, output_pcap):

        if process == 1 or process == 3:
            result_current_datetime = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            log_folder = f"mkdir {result_path}/{result_current_datetime}"
            os.system(log_folder)

            if process == 1:
                command = f"docker run --name suricata --rm -v /home/florian/Projets/spqr:/data  --entrypoint suricata suricata-6.0.15 -r /data/output/{nom_dossier}/pcap/{file_pcap_name} -c /data/config/suricata-6.0.15.yaml -S /data/config/suricata.rules -l /data/output/{nom_dossier}/result/{result_current_datetime}  -v -k none"
                print(f"Test du jeu de règle sur le pcap fourni réalisé")

            elif process == 3:
                command = f"docker run --name suricata --rm -v /home/florian/Projets/spqr:/data  --entrypoint suricata suricata-6.0.15 -c /data/config/suricata-6.0.15.yaml -S /data/config/suricata.rules -l /data/output/{nom_dossier}/result/{result_current_datetime}  -v -k none --engine-analysis"
                print(f"Test de la syntaxe du jeu de règle réalisée")

            else:
                pass
        
            os.system(command)
            print(f"les résultats sont disponible dans le dossier {result_path}/{result_current_datetime}") 

        elif process == 2:
            file = pathlib.Path(pcap_path +"/"+ output_pcap)
            if os.path.exists(file):
                result_current_datetime = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                log_folder = f"mkdir {result_path}/{result_current_datetime}"
                os.system(log_folder)
                command = f"docker run --name suricata --rm -v /home/florian/Projets/spqr:/data  --entrypoint suricata suricata-6.0.15 -r /data/output/{nom_dossier}/pcap/{output_pcap} -c /data/config/suricata-6.0.15.yaml -S /data/config/suricata.rules -l /data/output/{nom_dossier}/result/{result_current_datetime}  -v -k none"
                print(f"Test du jeu de règle sur le pcap généré réalisé")
                os.system(command)
                print(f"les résultats sont disponible dans le dossier {result_path}/{result_current_datetime}") 
            else:    
                print(f"Le fichier pcap n'existe pas encore.")

        else:
            print("Une erreur est survenue")
            
class SnortExecution:
    def __init__(self):
        pass

    def snort_execution(self, version, pcap_file, output_dir):
        if version == 2:
            command = f"docker run --rm -v $(pwd):/data snort2 snort -r /data/{pcap_file} -c /etc/snort/snort.conf -l /data/{output_dir}"
        elif version == 3:
            command = f"docker run --rm -v $(pwd):/data snort3 snort -R /data/{pcap_file} -c /etc/snort/snort.lua -l /data/{output_dir}"
        else:
            print("Version de Snort non prise en charge.")
            return
        os.system(command)

