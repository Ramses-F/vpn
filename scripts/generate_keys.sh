#!/bin/bash
set -e

KEY_DIR="keys"
mkdir -p $KEY_DIR

echo "🔐 Génération de la paire de clés RSA (2048 bits)..."

# Clé serveur
openssl genrsa -out $KEY_DIR/server_private.key 2048
openssl rsa -in $KEY_DIR/server_private.key -pubout -out $KEY_DIR/server_public.key

# Clé client
openssl genrsa -out $KEY_DIR/client_private.key 2048
openssl rsa -in $KEY_DIR/client_private.key -pubout -out $KEY_DIR/client_public.key

echo "✅ Clés générées dans le dossier '$KEY_DIR'"
