import streamlit as st
import pandas as pd
import os
import zipfile
import json
import logging
import subprocess
import requests
import tarfile
import io
from pathlib import Path
from scripts.utils.common import abs_path, load_json_or_yaml
from scripts.process.process import SPQRSimple
from datetime import datetime
from typing import Dict, List, Any, Optional
from scripts.utils.file_watcher import FileWatcher
import yaml  # Ajout de l'import yaml

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# === UTILITAIRES FACTORISÉS ===

def abs_path(path: Union[str, Path]) -> Path:
    """Retourne un chemin absolu résolu."""
    return Path(path).expanduser().resolve()

def load_json_or_yaml(config_path: Path) -> dict:
    """Charge indifféremment du JSON ou du YAML selon l'extension."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    if config_path.suffix in ('.yaml', '.yml'):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    else:
        with open(config_path, 'r') as f:
            return json.load(f)

def display_config_block(d: dict, key_prefix: str = "", help_map: dict = None) -> dict:
    """Affiche dynamiquement les entrées d'un dict dans Streamlit, retourne les valeurs éditées."""
    vals = {}
    help_map = help_map or {}
    for key, value in d.items():
        field_label = f"{key_prefix} {key}".replace("_", " ").capitalize()
        if isinstance(value, bool):
            vals[key] = st.checkbox(field_label, value, help=help_map.get(key, ""))
        elif isinstance(value, int):
            vals[key] = st.number_input(field_label, value=value, help=help_map.get(key, ""))
        elif isinstance(value, dict):
            try:
                vals[key] = json.loads(
                    st.text_area(field_label, value=json.dumps(value, indent=2), help=help_map.get(key, ""))
                )
            except:
                st.error(f"Format JSON invalide pour {key}")
        else:
            vals[key] = st.text_input(field_label, str(value), help=help_map.get(key, ""))
    return vals

def parse_custom_rule_input(rules: Optional[str], uploaded_file: Optional[Any]) -> Optional[str]:
    """Unifie le parsing d'une règle custom saisie (zone texte) ou uploadée."""
    if uploaded_file is not None:
        return uploaded_file.getvalue().decode() if hasattr(uploaded_file, 'getvalue') else uploaded_file.read()
    if rules:
        return rules
    return None

def get_protocol_config(spqr_web, attack_type: str) -> dict:
    """Retourne la config de protocole selon le type d'attaque."""
    protocol_type = spqr_web.config["traffic_patterns"][attack_type].get("payload_type", "http")
    return spqr_web.protocol_configs.get(protocol_type, {"default":{}, "attacks":{}}), protocol_type

# ==== CLASSE PRINCIPALE ====

class SPQRWeb:
    def __init__(self):
        self.spqr = SPQRSimple()
        self.file_watcher = FileWatcher()
        self.load_config()
        
    def load_config(self):
        """Load main config and protocol configs (JSON ou YAML)"""
        try:
            config_path = abs_path("config/config.json")
            self.file_watcher.add_watch(str(config_path))
            self.config = load_json_or_yaml(config_path)
            self.protocol_configs = {}
            for protocol in ["http", "dns", "icmp", "quic"]:
                p_path = abs_path(f"config/protocols/{protocol}_config.json")
                self.file_watcher.add_watch(str(p_path))
                try:
                    self.protocol_configs[protocol] = load_json_or_yaml(p_path)
                except (json.JSONDecodeError, FileNotFoundError, yaml.YAMLError) as e:
                    logger.warning(f"Config issue for {protocol}: {str(e)}")
                    self.protocol_configs[protocol] = {"default": {}, "attacks": {}}
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            raise

    def get_available_engines(self) -> List[Dict]:
        """Get list of configured IDS engines"""
        return self.config.get("engines", [
            {"type": "suricata", "version": "6.0.15"},
            {"type": "suricata", "version": "7.0.2"},
            {"type": "snort", "version": "2.9"},
            {"type": "snort", "version": "3"}
        ])

    def analyze_pcap(self, pcap_path: str, engine: str, rules: str = None, custom_rules_file: Any = None) -> dict:
        """Wrapper pour l'analyse PCAP, délègue à SPQRSimple"""
        try:
            logger.debug(f"Starting analysis with engine: {engine} - PCAP: {pcap_path}")
            if not abs_path(pcap_path).exists():
                raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

            custom_rules = parse_custom_rule_input(rules, custom_rules_file)
            results = self.spqr.analyze_pcap(pcap_path, engine, rules=custom_rules, custom_rules_file=None)
            if not results:
                logger.warning(f"No results returned for {engine}")
                return {"alerts": []}
            logger.debug(f"Analysis results for {engine}: {results}")
            return results
        except Exception as e:
            logger.exception(f"Error in analyze_pcap for {engine}")
            raise

    def _parse_ids_alerts(self, log_content: str, engine_type: str) -> list:
        """Parse alertes IDS (factorisé unique)"""
        return parse_ids_alerts(log_content, engine_type)

# ===== INTERFACE STREAMLIT =====

def show_pcap_generation():
    st.header("🔰 Générateur de PCAP")
    spqr = spqr_web.spqr

    # Choix du type de trafic (facteurs & factorisation config)
    traffic_types = spqr.list_attack_types()
    default_types = [t for t in traffic_types if t.endswith("_default")]
    attack_types = [t for t in traffic_types if not t.endswith("_default")]

    # Sélection catégorie
    traffic_category = st.radio(
        "Catégorie de trafic",
        ["Trafic personnalisé", "Trafic malveillant"],
        help="Choisissez entre du trafic normal ou des simulations d'attaque"
    )
    
    if traffic_category == "Trafic personnalisé":
        attack_type = st.selectbox("Type de trafic à générer", default_types, format_func=lambda x: x.replace("_default", "").upper())
    else:
        attack_type = st.selectbox("Type de trafic à générer", attack_types)

    st.info(spqr_web.config["traffic_patterns"][attack_type]["description"])
    protocol_config, protocol_type = get_protocol_config(spqr_web, attack_type)
    options = {}

    # Bloc configuration protocole (facteur)
    with st.expander(f"Configuration {protocol_type.upper()}", expanded=True):
        edited_config = display_config_block(protocol_config["default"])
        attacks_params = protocol_config.get("attacks", {}).get(attack_type, {}).get("parameters", {})
        if attacks_params:
            st.markdown("#### Paramètres spécifiques à l’attaque")
            edited_config.update(display_config_block(attacks_params, key_prefix="attack_"))

    # Bloc configuration réseau
    st.subheader("Paramètres réseau")
    network_config = display_config_block(spqr_web.config["network"], key_prefix="network_")

    # Bloc options de génération
    st.subheader("Options")
    if protocol_type in ("http", "dns", "icmp", "quic"):
        option_map = {
            "http": dict(packet_count=10, time_interval=100),
            "dns": dict(packet_count=5),
            "icmp": dict(packet_count=5),
            "quic": dict(time_interval=100)
        }
        for key, defval in option_map.get(protocol_type, {}).items():
            if "count" in key:
                options[key] = st.number_input(f"{key.replace('_', ' ').capitalize()}", 1, 1000, defval)
            elif "interval" in key:
                options[key] = st.slider(f"{key.replace('_', ' ').capitalize()} (ms)", 0, 1000, defval)
    else:
        options = {"packet_count": 1}

    # Génération
    if st.button("🚀 Générer PCAP"):
        with st.spinner("Génération du fichier PCAP en cours..."):
            try:
                generation_config = {
                    "network": network_config,
                    "protocol": edited_config,
                    "options": options
                }
                result = spqr.generate_pcap(
                    attack_type,
                    config=generation_config
                )
                if isinstance(result, dict) and 'error' in result:
                    st.error(f"❌ Erreur: {result['error']}")
                    return
                if isinstance(result, dict) and 'pcap_file' in result:
                    pcap_path = abs_path(result['pcap_file'])
                    if not pcap_path.exists():
                        st.error("❌ Le fichier PCAP n'a pas été créé")
                        return
                    st.success("✅ PCAP généré avec succès!")
                    st.metric("Taille", f"{pcap_path.stat().st_size / 1024:.2f} KB")
                    st.metric("Paquets", options.get("packet_count") or "?")
                    st.download_button(
                        "📥 Télécharger PCAP",
                        data=pcap_path.read_bytes(),
                        file_name=pcap_path.name,
                        mime="application/vnd.tcpdump.pcap"
                    )
                else:
                    st.error("❌ Format de résultat invalide")
            except Exception as e:
                logger.exception("Error during PCAP generation")
                st.error(f"❌ Erreur: {str(e)}")

def show_protocol_config():
    st.header("⚙️ Configuration des Protocoles")
    protocol = st.selectbox("Protocole à configurer", ["HTTP", "DNS", "ICMP", "QUIC"])
    config_path = abs_path(f"config/protocols/{protocol.lower()}_config.json")
    config = load_json_or_yaml(config_path)
    st.subheader("Configuration par défaut")
    edited_config = {}
    with st.expander("Valeurs par défaut", expanded=True):
        edited_config["default"] = display_config_block(config["default"])
    st.subheader("Configurations d'attaque")
    edited_config["attacks"] = {}
    for attack_name, attack_config in config.get("attacks", {}).items():
        with st.expander(f"Attaque: {attack_name}"):
            edited_config["attacks"][attack_name] = display_config_block(attack_config)
    if st.button("💾 Sauvegarder la configuration"):
        with open(config_path, "w") as f:
            json.dump(edited_config, f, indent=2)
        st.success("Configuration sauvegardée!")

def show_ids_testing():
    st.header("🔍 Test de règle IDS")
    st.subheader("Sélection des sondes IDS")
    engines_labels = [
        "Suricata 6.0.15", "Suricata 7.0.2", "Snort 2.9", "Snort 3"
    ]
    selected_engines = st.multiselect("Sondes IDS", engines_labels)
    st.subheader("Sélection du PCAP")
    pcap_dir = abs_path("output/pcap")
    pcap_files = list(pcap_dir.glob("*.pcap")) if pcap_dir.exists() else []
    pcap_path = st.selectbox("Sélectionner un PCAP généré", pcap_files, format_func=lambda x: x.name) if pcap_files else None

    if selected_engines and pcap_path:
        st.subheader("Règles IDS par moteur")
        rule_cols = st.columns(len(selected_engines))
        engine_rules = {}
        for idx, engine in enumerate(selected_engines):
            with rule_cols[idx]:
                st.markdown(f"##### {engine}")
                rule_source = st.radio(
                    f"Source des règles pour {engine}",
                    ["Règles par défaut", "Règle personnalisée", "Fichier de règles"],
                    key=f"rule_source_{engine}"
                )
                custom_rule, uploaded_file = None, None
                if rule_source == "Règle personnalisée":
                    custom_rule = st.text_area("Règle personnalisée", key=f"custom_{engine}", height=100)
                elif rule_source == "Fichier de règles":
                    uploaded_file = st.file_uploader("Fichier de règles", type=["rules", "txt"], key=f"upload_{engine}")
                engine_rules[engine] = {
                    "type": rule_source,
                    "custom_rule": custom_rule,
                    "uploaded_file": uploaded_file
                }

        if st.button("🚀 Lancer l'analyse"):
            for engine in selected_engines:
                r = engine_rules[engine]
                parsed_rule = parse_custom_rule_input(r.get("custom_rule"), r.get("uploaded_file"))
                try:
                    results = spqr_web.analyze_pcap(
                        pcap_path=str(abs_path(pcap_path)),
                        engine=engine,
                        rules=parsed_rule if r["type"] != "Règles par défaut" else None,
                        custom_rules_file=None  # Gestion factorisée
                    )
                    st.success(f"Analyse terminée pour {engine} - {len(results.get('alerts', []))} alertes")
                    if results.get("alerts"):
                        st.dataframe(pd.DataFrame(results["alerts"]))
                        st.download_button(
                            f"Télécharger logs {engine}",
                            "\n".join(str(a) for a in results["alerts"]),
                            file_name=f"analysis_logs_{engine.lower().replace(' ', '_')}.txt",
                            mime="text/plain"
                        )
                    else:
                        st.info("Aucune alerte détectée")
                except Exception as e:
                    st.error(f"Erreur pour {engine}: {str(e)}")

def show_home():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if abs_path("assets/spqr_logo.png").exists():
            st.image(str(abs_path("assets/spqr_logo.png")), width=300)
        st.title("🛡️ SPQR")
        st.markdown("*Une suite d'outils pour la sécurité réseau*")
    st.markdown("## 📚 Modules disponibles")
    module_col1, module_col2 = st.columns(2)
    with module_col1:
        st.markdown("""
        ### 🔰 Générateur de PCAP
        Générez facilement du trafic réseau pour vos tests.
        > Utilisez la navigation latérale pour accéder au générateur
        """)
    with module_col2:
        st.markdown("""
        ### 🔍 Test de règles IDS
        Testez vos règles de détection (Suricata/Snort).
        > Utilisez la navigation latérale pour accéder au testeur
        """)
    st.markdown("## 📊 Statistiques")
    stat_col1, stat_col2, stat_col3 = st.columns(3)
    pcap_count = len(list(abs_path("output/pcap").glob("*.pcap"))) if abs_path("output/pcap").exists() else 0
    rules_count = sum(1 for p in abs_path("config").rglob("*.rules") 
                     for l in p.read_text().splitlines() if l.strip() and not l.startswith('#'))
    docker_images = subprocess.run(
        ["docker", "images", "spqr_*", "--format", "{{.Repository}}"],
        capture_output=True, text=True
    ).stdout.count('\n')
    with stat_col1:
        st.metric("PCAPs générés", pcap_count)
    with stat_col2:
        st.metric("Règles disponibles", rules_count)
    with stat_col3:
        st.metric("Images Docker", docker_images)

def main():
    st.set_page_config(
        page_title="SPQR - Security Package for Quick Response",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    global spqr_web
    spqr_web = SPQRWeb()
    
    # Vérifier/construire les images Docker
    if not spqr_web.spqr.ensure_docker_images():
        st.error("❌ Erreur lors de la construction des images Docker")
        st.stop()
        
    if 'page' not in st.session_state:
        st.session_state.page = "Accueil"
    with st.sidebar:
        st.title("SPQR Navigation")
        selected = st.radio("Navigation", ["Accueil", "Génération PCAP", "Test de règle IDS"])
        st.session_state.page = selected
    if st.session_state.page == "Accueil":
        show_home()
    elif st.session_state.page == "Génération PCAP":
        show_pcap_generation()
    elif st.session_state.page == "Test de règle IDS":
        show_ids_testing()

# === ALERT PARSER FACTORISÉ ===
def parse_ids_alerts(log_content: str, engine_type: str) -> list:
    """Parse alerts from Suricata or Snort log (factorisé)."""
    alerts = []
    for line in log_content.splitlines():
        if not line.strip():
            continue
        try:
            if engine_type.lower().startswith("suricata"):
                # Try to parse JSON first
                try:
                    entry = json.loads(line)
                    if entry.get("event_type") == "alert":
                        alerts.append(entry)
                        continue
                except Exception:
                    pass  # fallback below
            parts = line.split("[**]")
            if len(parts) < 2:
                continue
            timestamp = parts[0].strip()
            rule_parts = [p.strip() for p in parts[1].split("]") if p]
            msg = rule_parts[-1] if rule_parts else "Unknown"
            alerts.append({
                "timestamp": timestamp,
                "message": msg,
                "rule": rule_parts[0] if rule_parts else "Unknown",
                "priority": rule_parts[2][9:] if len(rule_parts) > 2 and rule_parts[2].startswith("priority:") else "Unknown"
            })
        except Exception as e:
            logger.warning(f"Failed to parse alert line: {line[:100]}... Error: {str(e)}")
            continue
    return alerts

def verify_ids_config(engine: str) -> bool:
    """Vérifie et configure les moteurs IDS."""
    try:
        if engine.lower().startswith("suricata"):
            version = engine.split()[-1]
            config_dir = abs_path(f"config/suricata_{version}")
            if not config_dir.exists() or not (config_dir / "suricata.yaml").exists():
                st.error(f"Configuration Suricata {version} manquante")
                return False
            rules_dir = config_dir / "rules"
            if not rules_dir.exists() or not list(rules_dir.glob("*.rules")):
                if not download_et_rules(engine):
                    return False
        elif engine.lower().startswith("snort"):
            version = engine.split()[-1]
            config_dir = abs_path(f"config/snort_{version}")
            if not config_dir.exists():
                st.error(f"Configuration Snort {version} manquante")
                return False
        return True
    except Exception as e:
        logger.exception(f"Error verifying IDS config for {engine}")
        st.error(f"Erreur de configuration: {str(e)}")
        return False
    
def download_et_rules(engine: str) -> bool:
    """Télécharge les règles Emerging Threats."""
    try:
        version = engine.split()[-1]
        rules_url = "https://rules.emergingthreats.net/open/suricata-{}/rules/".format(version)
        rules_dir = abs_path(f"config/suricata_{version}/rules")
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        response = requests.get(f"{rules_url}/emerging-all.rules")
        if response.status_code == 200:
            rules_file = rules_dir / "suricata.rules"
            rules_file.write_text(response.text)
            st.success("✅ Règles Emerging Threats téléchargées")
            return True
        else:
            st.error("❌ Impossible de télécharger les règles")
            return False
    except Exception as e:
        logger.exception("Error downloading ET rules")
        st.error(f"Erreur de téléchargement: {str(e)}")
        return False
    
def get_engine_paths(engine: str) -> dict:
    """Retourne les chemins de configuration pour un moteur IDS."""
    version = engine.split()[-1]
    engine_type = engine.split()[0].lower()
    base_dir = abs_path(f"config/{engine_type}_{version}")
    return {
        "base": base_dir,
        "config": base_dir / f"{engine_type}.yaml",
        "rules": base_dir / "rules" / f"{engine_type}.rules",
        "output": abs_path("output") / engine_type / version
    }