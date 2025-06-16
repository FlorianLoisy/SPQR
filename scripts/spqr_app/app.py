import streamlit as st
import pandas as pd  # Add this import
import os
import zipfile
import json
import logging
import subprocess
from pathlib import Path
from scripts.process.process import SPQRSimple
from datetime import datetime
from typing import Dict, List, Any
from scripts.utils.file_watcher import FileWatcher  # Changed from relative to absolute import

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class SPQRWeb:
    def __init__(self):
        self.spqr = SPQRSimple()
        self.file_watcher = FileWatcher()
        self.load_config()
        
    def load_config(self):
        """Load main config and protocol configs"""
        try:
            # Add main config to file watcher
            config_path = "config/config.json"
            self.file_watcher.add_watch(config_path)
            
            with open(config_path) as f:
                self.config = json.load(f)
            
            # Load and watch protocol configs
            self.protocol_configs = {}
            for protocol in ["http", "dns", "icmp", "quic"]:
                config_path = f"config/protocols/{protocol}_config.json"
                self.file_watcher.add_watch(config_path)
                try:
                    with open(config_path) as f:
                        self.protocol_configs[protocol] = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError) as e:
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

    def analyze_pcap(self, pcap_path: str, engine: str, rules: str = None, custom_rules_file: str = None) -> dict:
        """Wrapper pour l'analyse PCAP, délègue à SPQRSimple"""
        return self.spqr.analyze_pcap(pcap_path, engine, rules, custom_rules_file)

    def _parse_ids_alerts(self, log_content: str, engine_type: str) -> list:
        """Parse les alertes IDS depuis le contenu du log"""
        alerts = []
        
        for line in log_content.splitlines():
            if not line.strip():
                continue
                
            try:
                if engine_type == "suricata":
                    # Format Suricata: timestamp [**] [rule] [classtype:type] [priority:n] msg [**] {proto} ip:port -> ip:port
                    parts = line.split("[**]")
                    if len(parts) < 2:
                        continue
                        
                    timestamp = parts[0].strip()
                    rule_parts = parts[1].strip().split("]")
                    msg = rule_parts[-1].strip() if rule_parts else "Unknown"
                    
                    alerts.append({
                        "timestamp": timestamp,
                        "message": msg,
                        "rule": rule_parts[0].strip("[") if rule_parts else "Unknown",
                        "priority": rule_parts[2].strip("[priority:").strip("]") if len(rule_parts) > 2 else "Unknown"
                    })
                    
                else:  # snort
                    # Format Snort: [timestamp] [rule] [classtype:type] [priority:n] {proto} ip:port -> ip:port
                    parts = line.split("[**]")
                    if len(parts) < 2:
                        continue
                        
                    alerts.append({
                        "timestamp": parts[0].strip(),
                        "message": parts[-1].strip(),
                        "rule": "Snort Alert",
                        "priority": "Unknown"
                    })
                    
            except Exception as e:
                logger.warning(f"Error parsing alert line: {str(e)}")
                continue
                
        return alerts

def show_pcap_generation():
    st.header("🔰 Générateur de PCAP")
    
    # Layout principal
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Regrouper les types de trafic par catégorie
        traffic_types = spqr_web.spqr.list_attack_types()
        default_types = [t for t in traffic_types if t.endswith("_default")]
        attack_types = [t for t in traffic_types if not t.endswith("_default")]
        
        # Sélection du type de trafic
        traffic_category = st.radio(
            "Catégorie de trafic",
            ["Trafic personnalisé", "Trafic malveillant"],
            help="Choisissez entre du trafic normal ou des simulations d'attaque"
        )
        
        if traffic_category == "Trafic personnalisé":
            attack_type = st.selectbox(
                "Type de trafic à générer",
                default_types,
                format_func=lambda x: x.replace("_default", "").upper(),
                help="Sélectionnez le protocole de base à générer"
            )

            # Configuration du protocole
            protocol_type = spqr_web.config["traffic_patterns"][attack_type].get("payload_type", "http")
            protocol_config = spqr_web.protocol_configs[protocol_type]

            # Interface de configuration du protocole personnalisé
            with st.expander(f"Configuration {protocol_type.upper()}", expanded=True):
                edited_config = {}
                
                # Utiliser des onglets pour séparer les configurations
                basic_tab, advanced_tab = st.tabs(["Configuration de base", "Paramètres avancés"])
                
                with basic_tab:
                    st.markdown("#### Configuration des paquets")
                    # Afficher et permettre l'édition de tous les paramètres par défaut
                    for key, value in protocol_config["default"].items():
                        edited_config[key] = _display_config_input(
                            key, 
                            value,
                            help=f"Modifier la valeur de {key} pour les paquets générés"
                        )
                
                with advanced_tab:
                    # Options spécifiques au protocole
                    if protocol_type == "http":
                        st.markdown("#### Configuration HTTP avancée")
                        edited_config["custom_headers"] = st.text_area(
                            "En-têtes personnalisés (JSON)",
                            value=json.dumps(protocol_config["default"].get("custom_headers", {}), indent=2),
                            help="Ajouter des en-têtes HTTP personnalisés au format JSON"
                        )
                    elif protocol_type == "dns":
                        st.markdown("#### Configuration DNS avancée")
                        edited_config["query_type"] = st.selectbox(
                            "Type de requête DNS",
                            ["A", "AAAA", "MX", "TXT", "CNAME"],
                            help="Sélectionner le type de requête DNS"
                        )
                    elif protocol_type == "icmp":
                        st.markdown("#### Configuration ICMP avancée")
                        edited_config["payload_size"] = st.number_input(
                            "Taille du payload (octets)",
                            min_value=0,
                            max_value=1400,
                            value=56,
                            help="Définir la taille du payload ICMP"
                        )
                    elif protocol_type == "quic":
                        st.markdown("#### Configuration QUIC avancée")
                        edited_config["version"] = st.selectbox(
                            "Version QUIC",
                            ["1", "2"],
                            help="Sélectionner la version du protocole QUIC"
                        )

        else:
            attack_type = st.selectbox(
                "Type de trafic à générer",
                attack_types,
                help="Sélectionnez le type d'attaque à simuler"
            )
        
        # Description du type sélectionné
        if attack_type in spqr_web.config["traffic_patterns"]:
            st.info(spqr_web.config["traffic_patterns"][attack_type]["description"])
            
        # Configuration du protocole
        protocol_type = spqr_web.config["traffic_patterns"][attack_type].get("payload_type", "http")
        protocol_config = spqr_web.protocol_configs[protocol_type]
        
        # Interface de configuration du protocole
        with st.expander(f"Configuration {protocol_type.upper()}", expanded=True):
            edited_config = {}
            
            try:
                # Configuration par défaut si attaque personnalisée
                if attack_type == "custom":
                    st.markdown("#### Configuration de base")
                    for key, value in protocol_config["default"].items():
                        edited_config[key] = _display_config_input(key, value)
                else:
                    # Afficher uniquement les paramètres spécifiques à l'attaque
                    attack_params = protocol_config["attacks"].get(attack_type, {}).get("parameters", {})
                    if attack_params:
                        st.markdown("#### Paramètres spécifiques")
                        for key, value in attack_params.items():
                            # Ne pas afficher les paramètres qui sont déjà dans la config par défaut
                            if key not in protocol_config["default"]:
                                edited_config[key] = _display_config_input(key, value)
                    
                    # Ajouter les paramètres par défaut nécessaires
                    for key, value in protocol_config["default"].items():
                        if key not in edited_config:
                            edited_config[key] = value
                            
            except Exception as e:
                logger.error(f"Error in protocol configuration: {str(e)}")
                st.error(f"Erreur de configuration: {str(e)}")
                return

    with col2:
        st.subheader("Paramètres réseau")
        try:
            # Paramètres de base pour tous les protocoles
            network_config = {
                "src_ip": st.text_input(
                    "IP Source",
                    value=spqr_web.config["network"].get("source_ip", "192.168.1.10")
                ),
                "dst_ip": st.text_input(
                    "IP Destination",
                    value=spqr_web.config["network"].get("dest_ip", "192.168.1.20")
                )
            }

            # Paramètres spécifiques au protocole
            if protocol_type == "icmp":
                # Ajout des adresses MAC pour ICMP
                network_config.update({
                    "src_mac": st.text_input(
                        "MAC Source (optionnel)",
                        value="",
                        help="Format: 00:11:22:33:44:55"
                    ),
                    "dst_mac": st.text_input(
                        "MAC Destination (optionnel)",
                        value="",
                        help="Format: 00:11:22:33:44:55"
                    )
                })
                # Supprimer les ports s'ils existent
                network_config.pop("src_port", None)
                network_config.pop("dst_port", None)
            else:
                # Ajouter les ports pour les autres protocoles
                network_config.update({
                    "src_port": st.number_input(
                        "Port Source",
                        value=int(spqr_web.config["network"].get("source_port", 1234))
                    ),
                    "dst_port": st.number_input(
                        "Port Destination",
                        value=int(spqr_web.config["network"].get("dest_port", 80))
                    )
                })

        except Exception as e:
            logger.error(f"Error in network configuration: {str(e)}")
            st.error(f"Erreur de configuration réseau: {str(e)}")
            return

        # Options de génération
        st.subheader("Options")
        options = {}
        
        # Définir quels protocoles utilisent quelles options
        protocol_options = {
            "http": ["packet_count", "time_interval"],
            "dns": ["packet_count"],
            "icmp": ["packet_count"],
            "quic": ["time_interval"]
        }
        
        # Afficher uniquement les options pertinentes pour le protocole
        if "packet_count" in protocol_options.get(protocol_type, []):
            options["packet_count"] = st.number_input(
                "Nombre de paquets", 
                1, 1000, 10,
                help="Nombre de paquets à générer"
            )
            
        if "time_interval" in protocol_options.get(protocol_type, []):
            options["time_interval"] = st.slider(
                "Intervalle (ms)", 
                0, 1000, 100,
                help="Intervalle entre les paquets"
            )
        
        # Si aucune option n'est définie, utiliser les valeurs par défaut
        if not options:
            options = {"packet_count": 1}

    # Bouton de génération
    if st.button("🚀 Générer PCAP"):
        with st.spinner("Génération du fichier PCAP en cours..."):
            try:
                # Log des configurations
                logger.debug(f"Attack type: {attack_type}")
                logger.debug(f"Protocol config: {edited_config}")
                logger.debug(f"Network config: {options}")
                logger.debug(f"Options: {options}")
                
                # Combiner toutes les configurations
                generation_config = {
                    "network": network_config,
                    "protocol": edited_config,
                    "options": options
                }
                
                # Générer le PCAP avec la configuration complète
                result = spqr_web.spqr.generate_pcap(
                    attack_type,
                    config=generation_config
                )
                
                logger.debug(f"Generation result: {result}")  # Add this line
                
                if isinstance(result, dict):
                    if 'error' in result:
                        st.error(f"❌ Erreur: {result['error']}")
                        logger.error(f"PCAP generation error: {result['error']}")
                        return
                        
                    if 'pcap_file' in result:
                        pcap_path = Path(result['pcap_file'])
                        if not pcap_path.exists():
                            st.error("❌ Le fichier PCAP n'a pas été créé")
                            logger.error(f"PCAP file not found: {pcap_path}")
                            return
                            
                        st.success(f"✅ PCAP généré avec succès!")
                        
                        # Afficher les détails du fichier
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Taille", f"{pcap_path.stat().st_size / 1024:.2f} KB")
                        with col2:
                            st.metric("Paquets", options["packet_count"])
                        with col3:
                            st.download_button(
                                "📥 Télécharger PCAP",
                                data=pcap_path.read_bytes(),
                                file_name=pcap_path.name,
                                mime="application/vnd.tcpdump.pcap"
                            )
                else:
                    st.error("❌ Format de résultat invalide")
                    logger.error(f"Invalid result format: {result}")
                    
            except Exception as e:
                logger.exception("Error during PCAP generation")
                st.error(f"❌ Erreur: {str(e)}")

def _display_config_input(key: str, value: Any, help: str = "") -> Any:
    """Affiche le widget approprié selon le type de valeur avec aide contextuelle"""
    if isinstance(value, bool):
        return st.checkbox(key, value, help=help)
    elif isinstance(value, int):
        return st.number_input(key, value=value, help=help)
    elif isinstance(value, dict):
        try:
            return json.loads(st.text_area(
                key,
                value=json.dumps(value, indent=2),
                help=help
            ))
        except json.JSONDecodeError:
            st.error(f"Format JSON invalide pour {key}")
            return value
    else:
        return st.text_input(key, str(value), help=help)

def show_protocol_config():
    st.header("⚙️ Configuration des Protocoles")
    
    # Sélection du protocole
    protocol = st.selectbox(
        "Protocole à configurer",
        ["HTTP", "DNS", "ICMP", "QUIC"]
    )
    
    # Charger la configuration actuelle
    config_path = f"config/protocols/{protocol.lower()}_config.json"
    with open(config_path) as f:
        config = json.load(f)
    
    # Interface d'édition
    st.subheader("Configuration par défaut")
    edited_config = {"default": {}}
    
    # Édition des valeurs par défaut
    with st.expander("Valeurs par défaut", expanded=True):
        for key, value in config["default"].items():
            if isinstance(value, bool):
                edited_config["default"][key] = st.checkbox(key, value)
            elif isinstance(value, int):
                edited_config["default"][key] = st.number_input(key, value=value)
            elif isinstance(value, dict):
                st.json(value)  # Pour l'instant, afficher uniquement
            else:
                edited_config["default"][key] = st.text_input(key, value)
    
    # Édition des configurations d'attaque
    st.subheader("Configurations d'attaque")
    edited_config["attacks"] = {}
    
    for attack_name, attack_config in config.get("attacks", {}).items():
        with st.expander(f"Attaque: {attack_name}"):
            edited_config["attacks"][attack_name] = {}
            for key, value in attack_config.items():
                edited_config["attacks"][attack_name][key] = st.text_input(
                    f"{attack_name} - {key}", 
                    value
                )
    
    # Bouton de sauvegarde
    if st.button("💾 Sauvegarder la configuration"):
        with open(config_path, "w") as f:
            json.dump(edited_config, f, indent=2)
        st.success("Configuration sauvegardée!")

def show_ids_testing():
    st.header("🔍 Test de règle IDS")
    
    # Sélection des sondes IDS d'abord pour organiser l'interface
    st.subheader("Sélection des sondes IDS")
    selected_engines = st.multiselect(
        "Sélectionner les sondes IDS à utiliser",
        ["Suricata 6.0.15", "Suricata 7.0.2", "Snort 2.9", "Snort 3"],
        help="Choisir une ou plusieurs sondes IDS pour l'analyse"
    )

    # Sélection du fichier PCAP
    st.subheader("Sélection du PCAP")
    pcap_source = st.radio(
        "Source du fichier PCAP",
        ["Fichier local", "Fichier généré"],
        help="Choisir un fichier PCAP local ou un fichier précédemment généré"
    )
    
    if pcap_source == "Fichier local":
        uploaded_pcap = st.file_uploader(
            "Charger un fichier PCAP",
            type=["pcap", "pcapng"],
            help="Glisser-déposer ou sélectionner un fichier PCAP"
        )
        if uploaded_pcap:
            # Sauvegarder le fichier temporairement
            temp_pcap = Path("output/temp") / uploaded_pcap.name
            temp_pcap.parent.mkdir(parents=True, exist_ok=True)
            temp_pcap.write_bytes(uploaded_pcap.getvalue())
            pcap_path = temp_pcap
        else:
            pcap_path = None
    else:
        # Liste des PCAPs générés
        pcap_dir = Path("/data/output/pcap")
        pcap_files = list(pcap_dir.glob("*.pcap"))
        if pcap_files:
            pcap_path = st.selectbox(
                "Sélectionner un PCAP généré",
                pcap_files,
                format_func=lambda x: x.name
            )
        else:
            st.warning("Aucun fichier PCAP généré trouvé")
            pcap_path = None

    # Configuration des règles par IDS sélectionné
    if selected_engines:
        st.subheader("Configuration des règles par IDS")
        
        # Créer des colonnes en fonction du nombre d'IDS sélectionnés
        rule_cols = st.columns(len(selected_engines))
        
        # Dictionnaire pour stocker les configurations de règles par moteur
        engine_rules = {}
        
        for idx, engine in enumerate(selected_engines):
            with rule_cols[idx]:
                st.markdown(f"##### {engine}")
                rule_source = st.radio(
                    f"Source des règles pour {engine}",
                    ["Règles par défaut", "Règle personnalisée", "Fichier de règles"],
                    key=f"rule_source_{engine}",
                    help=f"Choisir la source des règles pour {engine}"
                )
                
                if rule_source == "Règles par défaut":
                    # Liste des fichiers de règles disponibles pour cet IDS
                    engine_path = engine.lower().replace(" ", "_")
                    rules_dir = Path(f"config/{engine_path}/rules")
                    rule_files = list(rules_dir.glob("*.rules"))
                    selected_rules = st.multiselect(
                        "Fichiers de règles",
                        rule_files,
                        format_func=lambda x: x.name,
                        key=f"rules_{engine}"
                    )
                    engine_rules[engine] = {
                        "type": "default",
                        "rules": selected_rules
                    }
                    
                elif rule_source == "Règle personnalisée":
                    custom_rule = st.text_area(
                        "Règle personnalisée",
                        key=f"custom_{engine}",
                        height=100,
                        help="Entrer une règle au format Suricata/Snort"
                    )
                    engine_rules[engine] = {
                        "type": "custom",
                        "rules": custom_rule
                    }
                    
                else:  # Fichier de règles
                    uploaded_rules = st.file_uploader(
                        "Fichier de règles",
                        type=["rules", "txt"],
                        key=f"upload_{engine}",
                        help="Charger un fichier de règles"
                    )
                    engine_rules[engine] = {
                        "type": "file",
                        "rules": uploaded_rules
                    }

    # Bouton d'analyse
    if st.button("🚀 Lancer l'analyse"):
        if not pcap_path:
            st.error("Veuillez sélectionner un fichier PCAP")
            return
            
        if not selected_engines:
            st.error("Veuillez sélectionner au moins une sonde IDS")
            return

        # Conteneurs pour les résultats
        analysis_results = {}
        analysis_errors = {}
        analysis_stats = {
            "total": len(selected_engines),
            "success": 0,
            "failed": 0
        }

        # Analyse avec chaque sonde sélectionnée
        progress_container = st.container()
        progress_text = progress_container.empty()
        progress_bar = progress_container.progress(0)

        # Créer un conteneur pour les statuts d'analyse
        status_cols = st.columns(len(selected_engines))
        status_indicators = {}

        # Initialiser les indicateurs de statut pour chaque moteur
        for idx, engine in enumerate(selected_engines):
            with status_cols[idx]:
                st.markdown(f"##### {engine}")
                status_indicators[engine] = st.empty()
                status_indicators[engine].info("⏳ En attente...")
        
        for idx, engine in enumerate(selected_engines):
            progress_text.text(f"Analyse avec {engine}... ({idx + 1}/{len(selected_engines)})")
            status_indicators[engine].warning("🔄 En cours d'analyse...")
            
            try:
                engine_rule = engine_rules.get(engine, {})
                if engine_rule["type"] == "default":
                    results = spqr_web.analyze_pcap(
                        pcap_path=str(pcap_path),
                        engine=engine,
                        rules=None,
                        custom_rules_file=None
                    )
                elif engine_rule["type"] == "custom":
                    results = spqr_web.analyze_pcap(
                        pcap_path=str(pcap_path),
                        engine=engine,
                        rules=engine_rule["rules"],
                        custom_rules_file=None
                    )
                else:  # file
                    results = spqr_web.analyze_pcap(
                        pcap_path=str(pcap_path),
                        engine=engine,
                        rules=None,
                        custom_rules_file=engine_rule["rules"]
                    )
                analysis_results[engine] = results
                analysis_stats["success"] += 1
                status_indicators[engine].success("✅ Analyse terminée")
            except Exception as e:
                error_details = {
                    "message": str(e),
                    "type": type(e).__name__,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "context": {
                        "pcap": str(pcap_path),
                        "rules_source": engine_rule["type"],
                        "selected_rules": str(engine_rule.get("rules"))
                    }
                }
                analysis_errors[engine] = error_details
                analysis_stats["failed"] += 1
                logger.error(f"Error analyzing with {engine}: {str(e)}")
                status_indicators[engine].error("❌ Erreur")
            finally:
                progress_bar.progress((idx + 1) / len(selected_engines))

        # Afficher les résultats après l'analyse
        if analysis_results or analysis_errors:
            st.markdown("---")
            st.subheader("📊 Résultats de l'analyse")
            
            # Métriques globales
            metric_cols = st.columns(3)
            with metric_cols[0]:
                st.metric("Total des analyses", analysis_stats["total"])
            with metric_cols[1]:
                st.metric("Succès", analysis_stats["success"])
            with metric_cols[2]:
                st.metric("Échecs", analysis_stats["failed"])

            # Onglets pour les succès et les échecs
            success_tab, error_tab = st.tabs(["✅ Analyses réussies", "❌ Analyses échouées"])

            with success_tab:
                if analysis_results:
                    for engine, results in analysis_results.items():
                        with st.expander(f"Résultats pour {engine}", expanded=False):
                            if results.get("alerts"):
                                # Convertir les alertes en DataFrame pour un meilleur affichage
                                df = pd.DataFrame(results["alerts"])
                                st.dataframe(df)
                                
                                # Bouton pour télécharger les logs
                                log_content = "\n".join([str(alert) for alert in results["alerts"]])
                                st.download_button(
                                    "📥 Télécharger les logs",
                                    log_content,
                                    file_name=f"analysis_logs_{engine.lower().replace(' ', '_')}.txt",
                                    mime="text/plain"
                                )
                            else:
                                st.info("Aucune alerte détectée")
                else:
                    st.info("Aucune analyse réussie")

            with error_tab:
                if analysis_errors:
                    for engine, error in analysis_errors.items():
                        with st.expander(f"Erreur pour {engine}", expanded=False):
                            # Afficher les détails de l'erreur
                            st.error(f"Message: {error['message']}")
                            st.text(f"Type: {error['type']}")
                            st.text(f"Timestamp: {error['timestamp']}")
                            
                            # Afficher le contexte directement
                            st.markdown("##### Détails du contexte")
                            st.json(error['context'])
                            
                            # Ajouter le bouton pour voir les logs bruts
                            show_logs = st.button(
                                "👁️ Voir les logs bruts",
                                key=f"show_logs_{engine}"
                            )
                            
                            if show_logs:
                                st.code(error['message'], language="text")
                            
                            # Bouton pour télécharger les logs d'erreur
                            error_content = json.dumps(error, indent=2)
                            st.download_button(
                                "📥 Télécharger les logs d'erreur",
                                error_content,
                                file_name=f"error_logs_{engine.lower().replace(' ', '_')}.json",
                                mime="application/json"
                            )
                else:
                    st.info("Aucune erreur d'analyse")
                    
def show_home():
    """Affiche la page d'accueil de SPQR"""
    
    # Logo et titre
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        try:
            if Path("assets/spqr_logo.png").exists():
                st.image("assets/spqr_logo.png", width=300)
        except Exception as e:
            logger.warning(f"Logo not found: {e}")
            st.title("🛡️ SPQR")
            
        st.title("Security Package for Quick Response")
        st.markdown("*Une suite d'outils pour la sécurité réseau*")

    # Présentation des modules
    st.markdown("## 📚 Modules disponibles")
    
    module_col1, module_col2 = st.columns(2)
    
    with module_col1:
        st.markdown("""
        ### 🔰 Générateur de PCAP
        
        Générez facilement du trafic réseau pour vos tests :
        - Trafic HTTP, DNS, ICMP et QUIC
        - Configuration personnalisée
        - Export au format PCAP
        
        > Utilisez la navigation latérale pour accéder au générateur
        """)

    with module_col2:
        st.markdown("""
        ### 🔍 Test de règles IDS
        
        Testez vos règles de détection :
        - Support Suricata et Snort
        - Règles personnalisées
        - Analyse des alertes
        
        > Utilisez la navigation latérale pour accéder au testeur
        """)

    # Statistiques
    st.markdown("## 📊 Statistiques")
    stat_col1, stat_col2, stat_col3 = st.columns(3)

    # Compter les PCAPs générés
    pcap_count = len(list(Path("output/pcap").glob("*.pcap"))) if Path("output/pcap").exists() else 0
    
    # Compter les règles disponibles
    rules_count = sum(1 for p in Path("config").rglob("*.rules") 
                     for l in p.read_text().splitlines() 
                     if l.strip() and not l.startswith('#'))
    
    # Compter les images Docker
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

    # Documentation rapide
    with st.expander("ℹ️ Guide rapide", expanded=True):
        st.markdown("""
        ### Comment utiliser SPQR ?

        1. **Générer du trafic** : Utilisez le générateur de PCAP pour créer des captures réseau
        2. **Tester des règles** : Validez vos règles IDS avec les captures générées
        3. **Analyser les résultats** : Consultez les alertes et affinez vos règles

        Pour plus d'informations, consultez la documentation complète.
        """)

def main():
    st.set_page_config(
        page_title="SPQR - Security Package for Quick Response",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize SPQR
    global spqr_web
    spqr_web = SPQRWeb()

    # Initialize session state for navigation
    if 'page' not in st.session_state:
        st.session_state.page = "Accueil"

    # Sidebar Navigation
    with st.sidebar:
        st.title("SPQR Navigation")
        selected = st.radio(
            "Navigation",
            ["Accueil", "Génération PCAP", "Test de règle IDS"]
        )
        st.session_state.page = selected

    # Main Content based on selection
    if st.session_state.page == "Accueil":
        show_home()
    elif st.session_state.page == "Génération PCAP":
        show_pcap_generation()
    elif st.session_state.page == "Test de règle IDS":
        show_ids_testing()

if __name__ == "__main__":
    main()

