#!/bin/bash

set -e

echo "[SPQR] Construction de toutes les images Docker pour les moteurs IDS..."

cd "$(dirname "$0")"  # Se positionner dans images_docker

build_image() {
  local dir=$1
  local tag=$2
  if [ -d "$dir" ]; then
    echo "🔧 Construction de l'image: $tag à partir de $dir"
    docker build -t "$tag" "$dir"
  else
    echo "⚠️ Dossier $dir introuvable, image $tag non construite."
  fi
}

build_image Docker_Suricata-6.0.15 suricata_6.0.15
build_image Docker_Suricata-7.0.2 suricata_7.0.2
build_image Docker_Snort-2.9 snort_2.9
build_image Docker_Snort-3 snort_3

echo "✅ Toutes les images disponibles ont été construites."

docker images | grep spqr
