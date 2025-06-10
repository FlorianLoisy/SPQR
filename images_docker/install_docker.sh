#!/bin/bash

# Script d'installation de Docker pour Debian/Ubuntu

set -e

echo "[INFO] Mise à jour des paquets..."
sudo apt-get update

echo "[INFO] Installation des dépendances nécessaires..."
sudo apt-get install -y ca-certificates curl gnupg lsb-release

echo "[INFO] Ajout de la clé GPG officielle de Docker..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "[INFO] Ajout du dépôt Docker..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

echo "[INFO] Installation de Docker..."
sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

echo "[INFO] Création du groupe docker (si nécessaire)..."
if ! getent group docker >/dev/null; then
  sudo groupadd docker
fi

echo "[INFO] Ajout de l'utilisateur '$USER' au groupe docker..."
sudo usermod -aG docker "$USER"

echo "[INFO] Réinitialisation de session nécessaire pour l’accès Docker sans sudo."
echo "👉 Veuillez exécuter : newgrp docker"

echo "[INFO] Correction des permissions du dossier ~/.docker (si présent)..."
mkdir -p "$HOME/.docker"
sudo chown "$USER":"$USER" "$HOME/.docker" -R
sudo chmod g+rwx "$HOME/.docker" -R

echo "[✅] Docker installé avec succès."
docker --version