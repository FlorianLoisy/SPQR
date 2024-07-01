#!/bin/bash

# Création de l'environnement virtuel spqr_venv avec les dépendances python adéquat.
# Pensez à modifier les droits du fichiers pour l'executer.

apt install python3-venv
python3 -m venv spqr_venv
cd spqr_venv/
source ./bin/activate
pip install scapy
pip install clear
pip install ipywidgets
pip install json
pip install datetime
pip install scapy.layers.http
pip install scapy
pip install --upgrade scapy
pip install lib
apt install libpcap-dev
apt install wireshark