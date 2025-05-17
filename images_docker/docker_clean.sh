#!/bin/bash
# Attention : Ce script supprime tout (conteneurs, images, volumes, réseaux). Utilise-le uniquement si tu es sûr de ne rien vouloir conserver.

echo "🧹 Nettoyage Docker en cours..."

# Arrêter tous les conteneurs
echo "🛑 Arrêt des conteneurs..."
docker stop $(docker ps -aq) 2>/dev/null

# Supprimer tous les conteneurs
echo "🗑️ Suppression des conteneurs..."
docker rm $(docker ps -aq) 2>/dev/null

# Supprimer toutes les images
echo "🖼️ Suppression des images..."
docker rmi -f $(docker images -aq) 2>/dev/null

# Supprimer tous les volumes non utilisés
echo "💾 Suppression des volumes non utilisés..."
docker volume prune -f

# Supprimer les réseaux inutilisés
echo "🌐 Suppression des réseaux non utilisés..."
docker network prune -f

# Nettoyage final
echo "♻️ Docker system prune..."
docker system prune -a -f --volumes

echo "✅ Nettoyage Docker terminé."
