import streamlit as st
import os
import zipfile
import json
from pathlib import Path
from scripts.process.process import SPQRSimple
from datetime import datetime

class SPQRWeb:
    def __init__(self):
        self.spqr = SPQRSimple()
        self.load_config()

    def load_config(self):
        with open("config/config.json") as f:
            self.config = json.load(f)

def main():
    st.set_page_config(
        page_title="SPQR - Security Package for Quick Response",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize SPQR
    spqr_web = SPQRWeb()

    # Sidebar
    with st.sidebar:
        st.title("SPQR Controls")
        
        # Attack Type Selection
        attack_type = st.selectbox(
            "Type d'attaque",
            spqr_web.spqr.list_attack_types()
        )
        
        # Quick Test Button
        if st.button("🚀 Lancer un test rapide"):
            with st.spinner("Génération et analyse en cours..."):
                try:
                    result = spqr_web.spqr.quick_test(attack_type)
                    st.session_state['last_result'] = result
                    if isinstance(result, dict):
                        if 'pcap_file' in result:
                            st.success(f"Test terminé avec succès! PCAP généré: {Path(result['pcap_file']).name}")
                            # Add debug info
                            st.info(f"Chemins utilisés:\n"
                                    f"PCAP: {os.path.abspath(result['pcap_file'])}\n"
                                    f"Logs: {os.path.abspath(result.get('log_file', 'N/A'))}")
                        else:
                            st.warning("Test terminé mais aucun fichier PCAP n'a été généré")
                            st.write("Résultat:", result)
                    else:
                        st.error("Format de résultat inattendu")
                        st.write("Résultat:", result)
                except Exception as e:
                    st.error(f"Erreur: {str(e)}")
                    # Add debug output
                    st.error(f"Détails de l'erreur: {type(e).__name__}")
                    import traceback
                    st.code(traceback.format_exc())

    # Main Content
    st.title("SPQR Dashboard")
    
    # Results Display
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 Dernière analyse")
        if 'last_result' in st.session_state:
            result = st.session_state['last_result']
            if isinstance(result, dict):
                if 'pcap_file' in result:
                    st.info(f"PCAP: {Path(result['pcap_file']).name}")
                if 'log_file' in result and os.path.exists(result['log_file']):
                    with open(result['log_file'], 'r') as f:
                        st.code(f.read())
    
    with col2:
        st.subheader("📊 Résultats historiques")
        output_dir = "output"
        if os.path.exists(output_dir):
            analyses = [d for d in os.listdir(output_dir) 
                       if os.path.isdir(os.path.join(output_dir, d))]
            
            if analyses:
                selected_analysis = st.selectbox(
                    "Analyses disponibles",
                    sorted(analyses, reverse=True)
                )
                
                result_path = os.path.join(output_dir, selected_analysis, "result")
                if os.path.exists(result_path):
                    # Display alerts summary
                    alerts_summary = []
                    for file in os.listdir(result_path):
                        if file.endswith((".json", ".txt")):
                            file_path = os.path.join(result_path, file)
                            with open(file_path, "r", errors="ignore") as f:
                                content = f.read()
                                alert_count = content.lower().count("alert")
                                alerts_summary.append((file, alert_count))
                    
                    if alerts_summary:
                        for filename, count in alerts_summary:
                            st.write(f"📄 **{filename}** : {count} alerte(s)")
                        
                        # Download button
                        zip_filename = f"{selected_analysis}_result.zip"
                        zip_path = os.path.join("/tmp", zip_filename)
                        
                        if st.button("📦 Télécharger les résultats"):
                            with zipfile.ZipFile(zip_path, "w") as zipf:
                                for root, _, files in os.walk(result_path):
                                    for file in files:
                                        full_path = os.path.join(root, file)
                                        arcname = os.path.relpath(full_path, result_path)
                                        zipf.write(full_path, arcname)
                            with open(zip_path, "rb") as f:
                                st.download_button(
                                    "💾 Télécharger l'archive ZIP",
                                    f,
                                    file_name=zip_filename
                                )

    # Configuration Display
    with st.expander("⚙️ Configuration"):
        st.json(spqr_web.config)

if __name__ == "__main__":
    main()

