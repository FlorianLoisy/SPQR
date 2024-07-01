import os
from os import path

'''
Ce fichier contient les class et fonctions permettant la génération automatique des dossiers de travail.
Par défaut les output des différents tests se font dans /spqr/output/<nom_dossier>/pcap/ et /spqr/output/<nom_dossier>/result/.
Pour modifier l'emplacement du dossier de sortie, il faudra modifier la valeur de la variable <volume> présent dans le fichier main.ipynb
'''

class FolderGenerator:
    def __init__(self):
        self.path = {} 
        self.pcap_path = ""
        self.result_path = ""

    def generate_folder(self, volume, nom_dossier):
        output_path = path.join(volume, "output", nom_dossier)
        self.pcap_path = path.join(output_path, "pcap")
        self.result_path = path.join(output_path, "result")
        self.path = {"pcap_path": self.pcap_path, "result_path": self.result_path}

        # Créez les répertoires s'ils n'existent pas
        os.makedirs(output_path, exist_ok=True)
        os.makedirs(self.pcap_path, exist_ok=True)
        os.makedirs(self.result_path, exist_ok=True)

        return self.path
