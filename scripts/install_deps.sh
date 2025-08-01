#!/bin/bash
set -e

echo "🔧 Installation des dépendances nécessaires..."

sudo apt update
sudo apt install -y build-essential libssl-dev openssl \
  net-tools iproute2 iptables iputils-ping \
  openvpn

echo "✅ Dépendances installées avec succès"
