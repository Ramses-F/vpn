#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "❌ Ce script doit être exécuté en root (sudo)" 
   exit 1
fi

IFACE="tun0"

echo "📡 Création de l'interface TUN : $IFACE"
ip tuntap add dev $IFACE mode tun
ip addr add 10.0.0.1/24 dev $IFACE
ip link set dev $IFACE up

echo "✅ Interface $IFACE configurée avec l'IP 10.0.0.1/24"
