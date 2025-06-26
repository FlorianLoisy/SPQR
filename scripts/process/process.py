import os
import json
import shutil
import subprocess
import logging
import streamlit as st
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from scapy.all import wrpcap
import pandas as pd
from scripts.utils.utils import abs_path
from scripts.generate_traffic import ProtocolGeneratorFactory
from scripts.generate_traffic.protocols.icmp_generator import ICMPGenerator

logger = logging.getLogger("SPQR")

def log_debug(*args):
    """Affiche un message dans l'interface Streamlit (et la console aussi pour debug CLI)"""
    message = " ".join(str(a) for a in args)
    st.text(message)
    print(message)

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

        log_file = self.analyze_pcap(pcap_path)
        if not log_file:
            return {"error": "Test échoué"}

        report_file = self.generate_report(log_file)

        return {
            "pcap_file": pcap_path,
            "log_file": log_file,
            "report_file": report_file
        }

    def generate_pcap(self, attack_type: str, config: dict) -> dict:
        """
        Génère un PCAP à partir d'un certain attack_type déclaré en config.
    
        Args:
            attack_type (str): Type de trafic à générer
            config (dict): Configuration plate contenant tous les paramètres

        Returns:
            dict: Résultat contenant le chemin du fichier PCAP ou une erreur
        """
        try:
            # 🔹 Cas particulier : ICMP planifié via fichier JSON
            if attack_type == "icmp_specifique":
                json_path = Path("config/config.json")
                output_dir = Path(self.config["output"]["pcap_dir"])
                output_dir.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pcap_file = output_dir / f"{attack_type}_{timestamp}.pcap"

                ICMPGenerator.generate_icmp_from_schedule(str(json_path), str(pcap_file))

                return {"pcap_file": str(pcap_file)}

        # 🔸 Config par défaut
            # Utiliser la config par défaut si nécessaire
            if config is None:
                config = {
                    "source_ip": "192.168.1.10",
                    "dest_ip": "192.168.1.20",
                    "source_port": 12345,
                    "dest_port": 80,
                    "packet_count": 1,
                    "time_interval": 0
                }
            # Récupérer le type de protocole depuis la configuration des patterns
            protocol_type = self.config["traffic_patterns"][attack_type].get("payload_type", "http")
        
            # Créer un dictionnaire de configuration pour le générateur
            generator_config = config.copy()  # Copier la config pour ne pas la modifier
        
            # Créer le générateur avec la configuration complète
            generator = ProtocolGeneratorFactory.create_generator(protocol_type, generator_config)
       
            # Générer les paquets
            packets = generator.generate()
            if not packets:
                return {"error": "Aucun paquet généré"}
            
            # Sauvegarder le PCAP
            output_dir = Path(self.config["output"]["pcap_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = output_dir / f"{attack_type}_{timestamp}.pcap"
            wrpcap(str(pcap_file), packets)
        
            return {"pcap_file": str(pcap_file)}
        
        except Exception as e:
            logger.error(f"Error generating PCAP: {str(e)}")
            return {"error": str(e)}

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

    def to_host_path(path: Path) -> str:
        container_base = Path("/app").resolve()
        host_base = Path(os.environ.get("HOST_PROJECT_PATH", "/app")).resolve()
        return str(path).replace(str(container_base), str(host_base))

    def _run_ids_analysis(self, pcap_path: str, engine: str, log_dir: Path, rules: str = None, custom_rules_file: str = None, cleanup: bool = True) -> dict:
        """
        Lance l’analyse IDS avec un moteur Dockerisé (Suricata ou Snort).

        Args:
            pcap_path (str): Chemin du fichier PCAP.
            engine (str): Format `nom_version` (ex: suricata_6.0.15).
            log_dir (Path): Dossier des logs à monter.
            rules (str): Règles inline (facultatif).
            custom_rules_file (BytesIO): Règles sous forme de fichier (facultatif).
            cleanup (bool): Supprime le répertoire temporaire à la fin.

        Returns:
            dict: Résultats avec alertes, log utilisé, image utilisée.
        """
        temp_dir = None
        try:
            # Extraire type/version
            
            engine_name, version = engine.lower().split("_", 1)
            image_name = f"spqr_{engine_name}{version.replace('.', '')}"

            if not os.path.exists(pcap_path):
                raise FileNotFoundError(f"❌ Le fichier PCAP n'existe pas : {pcap_path}")

            
            pcap_path = Path(pcap_path).resolve()
            pcap_host_abs = str(pcap_path)
            project_root = Path("/home/f.loisy/Projets/SPQR")  # ← Racine du projet SPQR
            log_debug("🔍 Project root: ", project_root)
            log_debug("🔍 Current file: ", Path(__file__).resolve())
            
            base_temp = (project_root / "temp").resolve()
            temp_dir = base_temp / f"spqr_analysis_{engine_name}{version.replace('.', '')}"
            temp_dir.mkdir(parents=True, exist_ok=True)
            pcap_path = Path(pcap_path).absolute()
            
            log_dir = Path(log_dir) if isinstance(log_dir, str) else log_dir
            log_dir = base_temp / log_dir
            log_dir.mkdir(parents=True, exist_ok=True)
 
            log_debug("📄 Fichier PCAP sélectionné : ", pcap_host_abs)
            log_debug("📁 Répertoire temporaire utilisé : ",temp_dir)
                        
            # Gestion des règles
             
            rules_dir = temp_dir / "rules"
            rules_dir.mkdir(parents=True, exist_ok=True)
            rules_filename = (f"{engine_name}.rules")
            rules_path = rules_dir / rules_filename

            if custom_rules_file:
                rules_path.write_bytes(custom_rules_file.getvalue())
            elif rules:
                rules_path.write_text(rules)
            else:
                default_rules = Path(f"config/{engine_name}_{version}/rules/{rules_filename}").absolute()
                if not default_rules.exists():
                    raise FileNotFoundError(f"❌ Fichier de règles introuvable : {default_rules}")
                rules_path.write_text(default_rules.read_text())
                
            # Préparation de la config
            config_name = "suricata.yaml" if engine_name == "suricata" else "snort.conf"
            config_path = Path(f"config/{engine_name}_{version}/{config_name}").absolute()
            if not config_path.exists():
                raise FileNotFoundError(f"No configuration file found at {config_path}")
                
            config_file = temp_dir / config_name
            log_debug("✔️ CONFIG PATH:", config_path)
            log_debug("✔️ COPIED TO:", config_file)
            shutil.copy2(config_path, config_file)
            log_debug("CONFIG SOURCE EXISTS:", config_path.exists(), config_path)
                
            # Construction de la commande
            volume_mounts = [
            "-v", f"{to_host_path(pcap_host_abs)}:/pcap/input.pcap",
            "-v", f"{to_host_path(temp_dir)}:/etc/{engine_name}",
            "-v", f"{to_host_path(log_dir)}:/var/log/{engine_name}"
        ]
            assert config_file.exists(), f"Le fichier de config {config_file} n'existe pas juste avant docker run"
            assert temp_dir.exists() and config_file.exists(), f"{temp_dir} or config missing before docker run"
            log_debug("✅ Tous les chemins sont valides avant exécution.")
            log_debug("📁 Liste des fichiers dans temp_dir :", list(temp_dir.glob("**/*")))

            if engine_name == "suricata":
                cmd = [
                    "docker", "run", "--rm",
                    *volume_mounts,
                    image_name,
                    "suricata" ,
                    "-c", f"/etc/{engine_name}/{config_name}",
                    "-S", f"/etc/{engine_name}/rules/{rules_filename}",
                    "-r", "/pcap/input.pcap",
                    "-l", f"/var/log/{engine_name}"
                ]
                log_file = log_dir / "fast.log"
                    
            elif engine_name == "snort":
                cmd = [
                    "docker", "run", "--rm",
                    #*volume_mounts,
                    image_name,
                    "snort",
                    "-c", f"/etc/{engine_name}/{config_name}",
                    "-r", "/input.pcap",
                    "-l", f"/var/log/{engine_name}"
                ]
                log_file = log_dir / "alert"
                
            else:
                raise ValueError(f"❌ Moteur IDS non pris en charge : {engine_name}")
                
            # Exécution
            log_debug(f"📄 Fichier config utilisé : {config_file}")
            log_debug(f"📄 Fichier rules utilisé : {rules_path}")
            log_debug(f"📁 Contenu du dossier temporaire : {[str(p) for p in temp_dir.glob('**/*')]}")
            log_debug(f"🔍 Exécution de : {' '.join(cmd)}")
            log_debug("📁 Contenu final temp_dir:", os.listdir(temp_dir))
            log_debug("📁 Contenu /etc/suricata sera visible dans le conteneur")
            log_debug("📁 Vérification avant exécution:")
#            log_debug("docker run --rm -v {}:/etc/suricata {} ls -l /etc/suricata".format(temp_dir, image_name))

            result = subprocess.run(cmd, check=True, capture_output=True)
            log_debug("📤 STDOUT:", result.stdout.decode())
            log_debug("📥 STDERR:", result.stderr.decode())
            log_debug(f"✅ Docker exécuté avec succès pour {engine_name}_{version}")

            # Lecture des alertes
            alerts = []
            if log_file.exists():
                with open(log_file) as f:
                    for line in f:
                        if line.strip():
                            alerts.append({"raw": line.strip()})

            return {
                "alerts": alerts,
                "engine": f"{engine_name}_{version}",
                "log_file": str(log_file),
                "image_used": image_name
            }
            
        except subprocess.CalledProcessError as e:
            log_debug(f"❌ Échec Docker : {e.stderr}")
            raise RuntimeError(f"IDS analysis failed: {e.stderr}")
        
        except Exception as e:
            logger.error(f"Error during IDS analysis: {str(e)}")
            raise
        
        finally:
            if cleanup and temp_dir and temp_dir.exists():
                shutil.rmtree(temp_dir)
        
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
    
