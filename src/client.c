#include "client.h"
#include "tun.h"
#include "crypto.h"
#include "network.h"
#include "config.h"
#include "logger.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>

#define BUF_SIZE 2000
#define IV_SIZE 16

static unsigned char aes_key[32]; // 256 bits
static int tun_fd, sock_fd;
static vpn_config_t config;

// Thread: Lit depuis TUN, chiffre, envoie au serveur
void *tun_to_server_thread(void *arg) {
    unsigned char buffer[BUF_SIZE];
    unsigned char ciphertext[BUF_SIZE + 32];
    unsigned char iv[IV_SIZE];

    while (1) {
        int len = tun_read(tun_fd, (char *)buffer, BUF_SIZE);
        if (len < 0) continue;

        RAND_bytes(iv, IV_SIZE); // Générer un IV unique
        int cipher_len = crypto_encrypt_aes(buffer, len, aes_key, iv, ciphertext);

        // Envoi IV + data
        if (network_send(sock_fd, iv, IV_SIZE) <= 0) break;
        if (network_send(sock_fd, ciphertext, cipher_len) <= 0) break;
    }

    return NULL;
}

// Thread: Lit depuis serveur, déchiffre, injecte dans TUN
void *server_to_tun_thread(void *arg) {
    unsigned char buffer[BUF_SIZE + 32];
    unsigned char plaintext[BUF_SIZE];
    unsigned char iv[IV_SIZE];

    while (1) {
        if (network_receive(sock_fd, iv, IV_SIZE) <= 0) break;
        int len = network_receive(sock_fd, buffer, BUF_SIZE + 32);
        if (len <= 0) break;

        int plain_len = crypto_decrypt_aes(buffer, len, aes_key, iv, plaintext);
        if (plain_len < 0) continue;

        tun_write(tun_fd, (char *)plaintext, plain_len);
    }

    return NULL;
}

int vpn_client_start(const char *config_path) {
    // Charger la configuration
    if (config_load(config_path, &config) < 0) {
        logger_error("Erreur chargement config");
        return -1;
    }

    // Initialiser crypto
    if (crypto_init() < 0) {
        logger_error("Initialisation crypto échouée");
        return -1;
    }

    // Connexion au serveur
    sock_fd = network_client_socket(config.server_ip, config.server_port);
    if (sock_fd < 0) {
        logger_error("Connexion serveur échouée");
        return -1;
    }
    logger_log("Connecté à %s:%d", config.server_ip, config.server_port);

    // Échange de clés pour la session AES
    if (crypto_exchange_keys(sock_fd, aes_key) < 0) {
        logger_error("Échange de clés AES échoué");
        close(sock_fd);
        return -1;
    }
    logger_log("Clé AES reçue et déchiffrée avec succès");

    // Création interface TUN
    tun_fd = tun_create(config.tun_name);
    if (tun_fd < 0) {
        logger_error("Échec création interface TUN");
        close(sock_fd);
        return -1;
    }
    logger_log("Interface TUN '%s' créée", config.tun_name);

    // Lancer les threads
    pthread_t t1, t2;
    pthread_create(&t1, NULL, tun_to_server_thread, NULL);
    pthread_create(&t2, NULL, server_to_tun_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(sock_fd);
    close(tun_fd);

    return 0;
}
