#!/bin/bash

CONFIG_DIR="./config"

# Crée le dossier de configuration s'il n'existe pas
mkdir -p "$CONFIG_DIR"

# Génère server.conf
cat > "$CONFIG_DIR/server.conf" << EOF
# Configuration du serveur VPN
server_ip = 10.0.0.1
server_port = 1194
tun_interface = tun0
private_key = keys/server.key
public_key = keys/server.pub
client_pub_key = keys/client.pub
EOF

# Génère client.conf
cat > "$CONFIG_DIR/client.conf" << EOF
# Configuration du client VPN
server_ip = 10.0.0.1
server_port = 1194
tun_interface = tun0
private_key = keys/client.key
public_key = keys/client.pub
server_pub_key = keys/server.pub
EOF

echo "✅ Fichiers server.conf et client.conf générés dans le dossier $CONFIG_DIR"
