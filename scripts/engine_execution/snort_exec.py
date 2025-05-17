import os
import datetime
import pathlib

class SnortExecution:
    def __init__(self):
        """Initialise une instance de SnortExecution"""
        pass

    def snort_execution(self, process, result_path, pcap_path, nom_dossier, file_pcap_name, output_pcap):
        result_current_datetime = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        result_dir = f"{result_path}/snort/{result_current_datetime}"
        os.makedirs(result_dir, exist_ok=True)

        if process == 1:
            # PCAP fourni manuellement
            pcap_file = f"/data/input/{file_pcap_name}"
            print("Test Snort sur un PCAP fourni.")
        elif process == 2:
            # PCAP généré
            pcap_file = f"/data/output/{nom_dossier}/pcap/{output_pcap}"
            print("Test Snort sur un PCAP généré.")
        elif process == 3:
            print("Analyse de syntaxe seule non prise en charge dans Snort.")
            return
        else:
            print("Process non reconnu pour Snort.")
            return

        command = (
            f"docker run --rm --name snort "
            f"-v /home/florian/Projets/spqr:/data "
            f"snort3:latest "
            f"snort -c /data/config/snort/snort.lua "
            f"-R /data/config/snort/snort.rules "
            f"-r {pcap_file} "
            f"-A unified2 "
            f"-l /data/output/{nom_dossier}/result/snort/{result_current_datetime} "
            f"-k none"
        )

        print(f"Commande exécutée : {command}")
        os.system(command)
        print(f"Les résultats sont disponibles dans : {result_dir}")
