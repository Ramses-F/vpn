#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <openssl/rsa.h>  // Pour le type RSA

// Initialise les bibliothèques cryptographiques
int crypto_init(void);

// Génère une paire de clés RSA et les sauvegarde dans des fichiers
int crypto_generate_rsa_keys(const char *private_key_file, const char *public_key_file);

// Chiffre un message avec AES-256-CBC
int crypto_encrypt_aes(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *ciphertext);

// Déchiffre un message avec AES-256-CBC
int crypto_decrypt_aes(const unsigned char *ciphertext, int ciphertext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *plaintext);

// Charge une clé RSA depuis un fichier (public = 1 pour clé publique, 0 pour clé privée)

EVP_PKEY *crypto_load_rsa_key(const char *file_path, int public);

// Effectue un échange de clés RSA (client/serveur)
// Envoie la clé AES chiffrée avec la clé publique du destinataire via socket
int crypto_exchange_keys(int socket_fd, unsigned char *session_key_out);

// Reçoit et déchiffre une clé AES chiffrée via socket avec la clé privée RSA
int crypto_receive_key(int socket_fd, unsigned char *session_key_out, EVP_PKEY *privkey);

#endif // CRYPTO_H
