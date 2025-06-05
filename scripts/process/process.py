import os
import datetime
import pathlib

'''
Ce fichier a été créé dans le but de réaliser les tâches dédiées aux processus de création de règle.
'''

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

