# 🔐 VPN en C - Tunnel sécurisé avec AES et RSA

Ce projet implémente un VPN simple en langage C, utilisant une interface TUN pour créer un tunnel IP chiffré entre un client et un serveur.  
Le trafic est sécurisé à l’aide du chiffrement **AES-256-CBC** et d’un échange de clés via **RSA**.

## 📌 Objectifs pédagogiques

- Comprendre le fonctionnement d’un tunnel VPN
- Utiliser les interfaces réseau TUN/TAP sous Linux
- Implémenter le chiffrement symétrique (AES) avec IV
- Mettre en place un échange de clé sécurisé (RSA)
- Manipuler les sockets TCP pour envoyer des paquets IP chiffrés

## 📂 Structure du projet

- `server.c` : code du serveur VPN
- `client.c` : code du client VPN
- `crypto.c` : fonctions de chiffrement AES/RSA
- `tun.c` : création et gestion de l’interface TUN
- `network.c` : communication via sockets
- `config/` : fichiers de configuration client et serveur
- `keys/` : clés RSA (privée et publique)

## 🔐 Sécurité

- Génération d’un IV aléatoire pour chaque paquet (AES CBC)
- Clé de session AES échangée via RSA
- Chiffrement bout-en-bout du trafic réseau

## ⚙️ Compilation

```bash
gcc -o server server.c crypto.c tun.c network.c -lssl -lcrypto -lpthread
gcc -o client client.c crypto.c tun.c network.c -lssl -lcrypto -lpthread

🚀 Utilisation
Lancer le serveur :

sudo ./server config/server.conf

Lancer le client :

sudo ./client config/client.conf

Assurez-vous d’avoir généré vos clés RSA au préalable.

🧪 Exemple de test

Après le lancement, vous pouvez tester la connectivité avec un ping entre les IPs des interfaces TUN.
📈 Améliorations possibles

    Gestion multi-clients

    Authentification utilisateur

    Compression de paquets

    Interface graphique

    Support UDP

    Support TLS avec certificats

👨‍💻 Auteur

Projet réalisé par Fallet Kamagaté, dans un but d’apprentissage de la programmation système, réseau et sécurité en C.
⚠️ Avertissement

Ce projet est à but éducatif uniquement. Ne pas utiliser en production sans vérification de la sécurité complète.


---

Tu veux que je t’aide à créer le dépôt (fichier `.gitignore`, structure, clé RSA exemple) ?
