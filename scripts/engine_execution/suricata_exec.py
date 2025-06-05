# Structure : scripts/engine_execution/suricata_exec.py
import os
import datetime
import pathlib

class SuricataExecution:
    def __init__(self):
        pass

    def suricata_execution(self, process, result_path, pcap_path, nom_dossier, file_pcap_name, output_pcap):
        result_current_datetime = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        log_folder = f"{result_path}/suricata/{result_current_datetime}"
        os.makedirs(log_folder, exist_ok=True)

        volume_base = "/home/florian/Projets/spqr"
        result_log = f"/data/output/{nom_dossier}/result/suricata/{result_current_datetime}"

        if process == 1:
            command = f"docker run --name suricata --rm -v {volume_base}:/data --entrypoint suricata suricata-6.0.15 -r /data/input/{file_pcap_name} -c /data/config/suricata-6.0.15.yaml -S /data/config/suricata.rules -l {result_log} -v -k none"
            print("[Suricata] Test du jeu de règles sur PCAP fourni")

        elif process == 2:
            file = pathlib.Path(f"{pcap_path}/{output_pcap}")
            if not os.path.exists(file):
                print("Le fichier pcap n'existe pas encore.")
                return
            command = f"docker run --name suricata --rm -v {volume_base}:/data --entrypoint suricata suricata-6.0.15 -r /data/output/{nom_dossier}/pcap/{output_pcap} -c /data/config/suricata-6.0.15.yaml -S /data/config/suricata.rules -l {result_log} -v -k none"
            print("[Suricata] Test du jeu de règles sur PCAP généré")

        elif process == 3:
            command = f"docker run --name suricata --rm -v {volume_base}:/data --entrypoint suricata suricata-6.0.15 -c /data/config/suricata-6.0.15.yaml -S /data/config/suricata.rules -l {result_log} -v -k none --engine-analysis"
            print("[Suricata] Analyse de la syntaxe des règles")

        else:
            print("[Suricata] Process non reconnu")
            return

        os.system(command)
        print(f"[Suricata] Résultats disponibles dans : {log_folder}")
