import streamlit as st
import os
import zipfile

# Dossier contenant les résultats des analyses
OUTPUT_DIR = "output"  # Mise à jour ici

st.set_page_config(page_title="SPQR - Résultats", layout="wide")
st.title("Visualisation des résultats SPQR")

# Liste des sous-dossiers dans OUTPUT_DIR
if not os.path.exists(OUTPUT_DIR):
    st.error("Le dossier 'output/' est introuvable. Assurez-vous qu'il est monté correctement.")
    st.stop()

analyses = [d for d in os.listdir(OUTPUT_DIR) if os.path.isdir(os.path.join(OUTPUT_DIR, d))]

if not analyses:
    st.info("Aucun résultat trouvé dans le dossier output/")
    st.stop()

selected_analysis = st.selectbox("Choisissez une analyse", sorted(analyses, reverse=True))

result_path = os.path.join(OUTPUT_DIR, selected_analysis, "result")

if not os.path.exists(result_path):
    st.warning(f"Aucun dossier de résultats trouvé pour {selected_analysis}")
    st.stop()

# Résumé rapide des fichiers journaux
st.subheader("Résumé des alertes")
alerts_summary = []
for file in os.listdir(result_path):
    if file.endswith(".json") or file.endswith(".txt"):
        file_path = os.path.join(result_path, file)
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
            alert_count = content.lower().count("alert")
            alerts_summary.append((file, alert_count))

if alerts_summary:
    for filename, count in alerts_summary:
        st.write(f"📄 **{filename}** : {count} alerte(s)")
else:
    st.write("Aucune alerte détectée ou fichiers non lisibles.")

# Ajout du bouton de téléchargement du dossier compressé
zip_filename = f"{selected_analysis}_result.zip"
zip_path = os.path.join("/tmp", zip_filename)

if st.button("📦 Télécharger les résultats en ZIP"):
    with zipfile.ZipFile(zip_path, "w") as zipf:
        for root, _, files in os.walk(result_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, result_path)
                zipf.write(full_path, arcname)
    with open(zip_path, "rb") as f:
        st.download_button("Télécharger l'archive ZIP", f, file_name=zip_filename)

