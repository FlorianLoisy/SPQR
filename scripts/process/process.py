import os
import json
import shutil
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from scapy.all import wrpcap
import pandas as pd
from scripts.utils.utils import abs_path
from scripts.generate_traffic import ProtocolGeneratorFactory

logger = logging.getLogger("SPQR")

class SPQRSimple:
    """
    Main class for SPQR functionality handling traffic generation and IDS analysis.
    """

    def __init__(self, config_file="config/config.json"):
        with open(config_file, "r") as f:
            self.config = json.load(f)

    # --- Méthode utilitaires publiques ---

    def list_attack_types(self) -> List[str]:
        """
        Liste tous les types de trafic disponibles
        """
        patterns = self.config.get("traffic_patterns", {})
        return sorted(
            patterns.keys(),
            key=lambda x: "0" if x.endswith("_default") else "1" + x
        )

    def get_timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def quick_test(self, attack_type: str) -> Dict:
        """
        Génère un trafic, le teste et renvoie les chemins des fichiers générés.
        """
        timestamp = self.get_timestamp()
        pcap_filename = f"{attack_type}_{timestamp}.pcap"
        pcap_path = os.path.join(self.config["output"]["pcap_dir"], pcap_filename)

        try:
            result = self.generate_pcap(attack_type)
            if "error" in result:
                return {"error": result["error"]}

            generated_pcap = result.get("pcap_file")
            if generated_pcap and generated_pcap != pcap_path:
                shutil.copy(generated_pcap, pcap_path)
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

    def generate_pcap(self, attack_type: str, config: Optional[Dict] = None) -> Dict:
        """
        Génère un PCAP à partir d'un certain attack_type déclaré en config.
        """
        try:
            if config is None:
                config = {
                    "network": self.config["network"],
                    "protocol": {},
                    "options": {"packet_count": 1, "time_interval": 0}
                }
            protocol_type = self.config["traffic_patterns"][attack_type].get("payload_type", "http")
            generator = ProtocolGeneratorFactory.create_generator(
                protocol_type=protocol_type,
                config={**config["network"], **config["protocol"]}
            )
            generator.set_options(config.get("options", {}))
            packets = generator.generate()
            if not packets:
                return {"error": "Aucun paquet généré"}
            output_dir = Path(self.config["pcap"]["output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = output_dir / f"{attack_type}_{timestamp}.pcap"
            wrpcap(str(pcap_file), packets)
            return {"pcap_file": str(pcap_file)}
        except Exception as e:
            logger.error(f"Error generating PCAP: {str(e)}")
            return {"error": str(e)}

    def test_rules(self, pcap_file: str, rules_file: str = None) -> str:
        """
        Lance un IDS sur le PCAP fourni avec les règles appropriées (par défaut: Suricata docker).
        """
        engine = self.config.get("engine", {})
        engine_type = engine.get("type", "suricata")
        version = engine.get("version", "6.0.15")
        mode = engine.get("mode", "docker")

        log_dir = Path(self.config["suricata"]["log_dir"]).absolute()
        config_path = Path(self.config["suricata"]["config_file"]).absolute()
        rules_path = Path(rules_file or self.config["suricata"]["rules_file"]).absolute()
        pcap_path = Path(pcap_file).absolute()

        if not pcap_path.is_file() or not config_path.is_file() or not rules_path.is_file():
            logger.error(f"Fichier manquant pour le test: pcap={pcap_path}, config={config_path}, rules={rules_path}")
            return None

        os.makedirs(log_dir, exist_ok=True)

        if mode == "docker":
            image = f"spqr_{engine_type}_{version}"
            cmd = [
                "docker", "run", "--rm",
                "--entrypoint", "sh", image,
                "-c", f"mkdir -p /etc/suricata/rules && suricata -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/suricata.rules -r /input.pcap -l /var/log/suricata",
                "-v", f"{pcap_path}:/input.pcap:ro",
                "-v", f"{config_path}:/etc/suricata/suricata.yaml:ro",
                "-v", f"{rules_path}:/etc/suricata/rules/suricata.rules:ro",
                "-v", f"{log_dir}:/var/log/suricata"
            ]
            try:
                subprocess.run(cmd, check=True, capture_output=True)
                return str(log_dir / "eve.json")
            except subprocess.CalledProcessError as e:
                logger.error(f"Command failed: {e.stdout}\n{e.stderr}")
                return None
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
                logger.error(f"Suricata failed: {e}")
                return None

    def generate_report(self, log_file: str) -> str:
        """
        Génère un rapport résumé à partir d'un fichier de log eve.json ou fast.log de Suricata.
        """
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

    def test_with_engine(self, pcap_file: str, engine_type: str, version: str) -> Dict:
        """
        Test PCAP with a specific engine (type and version)
        """
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

    def test_all_engines(self, pcap_file: str) -> Dict:
        """
        Test le même PCAP sur tous les moteurs déclarés dans la config.
        """
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

            try:
                log_file = self.test_rules(pcap_file)
                if not log_file:
                    results[engine_name] = {"error": "Échec du test"}
                    continue
                report_file = self.generate_report(log_file)
                results[engine_name] = {
                    "log_file": log_file,
                    "report_file": report_file
                }
            except Exception as e:
                logger.error(f"Erreur lors du test avec {engine_name}: {str(e)}")
                results[engine_name] = {"error": str(e)}
            finally:
                self.config["suricata"]["log_dir"] = log_dir_backup
                self.config["output"]["reports_dir"] = report_dir_backup

        return results

    # --- Méthodes avancées d'analyse ---

    def analyze_pcap(self, pcap_path: str, engine: str, rules: str = None, custom_rules_file: str = None) -> dict:
        """
        Analyse un fichier PCAP avec une sonde IDS et génère un rapport détaillé.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = Path(f"output/logs/{timestamp}/{engine.replace(' ', '_').lower()}")
        report_dir = log_dir / "report"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            report_dir.mkdir(parents=True, exist_ok=True)
            results = self._run_ids_analysis(
                pcap_path=pcap_path,
                engine=engine,
                log_dir=log_dir,
                rules=rules,
                custom_rules_file=custom_rules_file
            )
            report = {
                "metadata": {
                    "timestamp": timestamp,
                    "engine": engine,
                    "pcap_file": str(pcap_path),
                    "rules_source": "custom_file" if custom_rules_file else "inline" if rules else "default"
                },
                "analysis": results,
                "statistics": self._generate_statistics(results)
            }
            report_path = report_dir / "analysis_report.json"
            alerts_path = report_dir / "alerts.csv"
            summary_path = report_dir / "summary.txt"
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            if results.get("alerts"):
                pd.DataFrame(results["alerts"]).to_csv(alerts_path, index=False)
            summary = self._generate_summary(report)
            summary_path.write_text(summary)
            if (log_dir / "fast.log").exists():
                shutil.copy2(log_dir / "fast.log", report_dir / "ids.log")
            elif (log_dir / "alert").exists():
                shutil.copy2(log_dir / "alert", report_dir / "ids.log")
            return {
                "report_dir": str(report_dir),
                "alerts": results.get("alerts", []),
                "summary": summary
            }
        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}")
            raise

    # --- Méthodes privées de reporting/parse ---
    def _generate_statistics(self, results: dict) -> dict:
        """
        Génère des statistiques à partir des résultats d'analyse
        """
        alerts = results.get("alerts", [])
        return {
            "total_alerts": len(alerts),
            "severity_counts": {
                "high": sum(1 for a in alerts if a.get("severity") == "high"),
                "medium": sum(1 for a in alerts if a.get("severity") == "medium"),
                "low": sum(1 for a in alerts if a.get("severity") == "low")
            },
            "unique_signatures": len(set(a.get("signature", "") for a in alerts))
        }

    def _generate_summary(self, report: dict) -> str:
        """
        Génère un résumé humain lisible à partir d'un rapport d'analyse
        """
        stats = report["statistics"]
        return f"""SPQR Analysis Report Summary
========================
Timestamp: {report['metadata']['timestamp']}
Engine: {report['metadata']['engine']}
PCAP File: {report['metadata']['pcap_file']}

Analysis Results
--------------
Total Alerts: {stats['total_alerts']}
Severity Distribution:
- High: {stats['severity_counts']['high']}
- Medium: {stats['severity_counts']['medium']}
- Low: {stats['severity_counts']['low']}
Unique Signatures: {stats['unique_signatures']}

Generated by SPQR (Security Package for Quick Response)
"""

    def _run_ids_analysis(self, pcap_path: str, engine: str, log_dir: Path, rules: str = None, custom_rules_file: str = None) -> dict:
        """
        Run IDS analysis with specified engine and rules.
        """
        try:
            pcap_path = Path(pcap_path).absolute()
            log_dir = Path(log_dir).absolute()
            engine_name, version = engine.lower().split()
            image_name = f"spqr_{engine_name} {version.replace('.', '')}"
            temp_dir = Path("/tmp/spqr_analysis").absolute()
            temp_dir.mkdir(parents=True, exist_ok=True)
            try:
                rules_path = temp_dir / "custom.rules"
                if custom_rules_file:
                    rules_path.write_bytes(custom_rules_file.getvalue())
                elif rules:
                    rules_path.write_text(rules)
                else:
                    default_rules = Path(f"config/{engine_name}_{version}/rules/suricata.rules").absolute()
                    if default_rules.exists():
                        rules_path.write_text(default_rules.read_text())
                    else:
                        raise FileNotFoundError(f"No rules found at {default_rules}")
                config_path = Path(f"config/{engine_name}_{version}/suricata.yaml").absolute()
                if not config_path.exists():
                    raise FileNotFoundError(f"No configuration file found at {config_path}")
                temp_config = temp_dir / "suricata.yaml"
                shutil.copy2(config_path, temp_config)
                log_dir.mkdir(parents=True, exist_ok=True)
                cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{pcap_path}:/input.pcap:ro",
                    "-v", f"{rules_path}:/etc/suricata/rules/custom.rules:ro",
                    "-v", f"{temp_config}:/etc/suricata/suricata.yaml:ro",
                    "-v", f"{log_dir}:/var/log/suricata",
                    image_name,
                    "suricata" if engine_name == "suricata" else "snort",
                    "-c", "/etc/suricata/suricata.yaml" if engine_name == "suricata" else "/etc/snort/snort.conf",
                    "-S", "/etc/suricata/rules/custom.rules" if engine_name == "suricata" else None,
                    "-r", "/input.pcap",
                    "-l", "/var/log/suricata" if engine_name == "suricata" else "/var/log/snort"
                ]
                # Remove None and convert to str
                cmd = [str(arg) for arg in cmd if arg is not None]
                logger.debug(f"Running command: {' '.join(cmd)}")
                subprocess.run(cmd, check=True, capture_output=True)
                alerts = []
                log_file = log_dir / ("fast.log" if engine_name == "suricata" else "alert")
                if log_file.exists():
                    with open(log_file) as f:
                        for line in f:
                            if line.strip():
                                alerts.append({"raw": line.strip()})
                return {"alerts": alerts}
            finally:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
        except subprocess.CalledProcessError as e:
            logger.error(f"IDS analysis failed: {e.stdout}\n{e.stderr}")
            raise RuntimeError(f"IDS analysis failed: {e.stderr}")
        except Exception as e:
            logger.error(f"Error during IDS analysis: {str(e)}")
            raise
        
    def ensure_docker_images(self) -> bool:
        """Vérifie la présence des images Docker requises."""
        try:
            required_images = [
                "spqr_suricata6015",
                "spqr_suricata702",
                "spqr_snort29",
                "spqr_snort3"
            ]
            
            # Vérifier les images existantes
            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}"],
                capture_output=True,
                text=True,
                check=True
            )
            existing_images = result.stdout.splitlines()
            
            missing_images = [img for img in required_images if img not in existing_images]
            
            if not missing_images:
                logger.info("✅ All Docker images are present")
                return True
                
            logger.error(f"❌ Missing Docker images: {missing_images}")
            logger.error("Please run 'docker-compose build' manually")
            return False
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Docker command failed: {e.stderr}")
            return False
        except Exception as e:
            logger.exception("Error checking Docker images")
            return False
    
