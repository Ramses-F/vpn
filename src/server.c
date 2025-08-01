#include "server.h"
#include "tun.h"
#include "crypto.h"
#include "network.h"
#include "config.h"
#include "logger.h"
#include <utils.h>

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define BUF_SIZE 2000
#define IV_SIZE 16

typedef struct {
    int client_fd;
    unsigned char aes_key[32];
    int tun_fd;
} client_session_t;

// Thread: lit de TUN → chiffre → envoie au client
void *tun_to_client(void *arg) {
    client_session_t *session = (client_session_t *)arg;
    unsigned char buffer[BUF_SIZE];
    unsigned char ciphertext[BUF_SIZE + 32];  // marge pour padding
    unsigned char iv[IV_SIZE];

    while (1) {
        int len = tun_read(session->tun_fd, (char *)buffer, BUF_SIZE);
        if (len < 0) continue;

        RAND_bytes(iv, IV_SIZE);
        int cipher_len = crypto_encrypt_aes(buffer, len, session->aes_key, iv, ciphertext);

        network_send(session->client_fd, iv, IV_SIZE);
        network_send(session->client_fd, ciphertext, cipher_len);
    }

    return NULL;
}

// Thread: lit du client → déchiffre → injecte dans TUN
void *client_to_tun(void *arg) {
    client_session_t *session = (client_session_t *)arg;
    unsigned char buffer[BUF_SIZE + 32];
    unsigned char plaintext[BUF_SIZE];
    unsigned char iv[IV_SIZE];

    while (1) {
        if (network_receive(session->client_fd, iv, IV_SIZE) <= 0) continue;
        int len = network_receive(session->client_fd, buffer, BUF_SIZE + 32);
        if (len <= 0) continue;

        int plain_len = crypto_decrypt_aes(buffer, len, session->aes_key, iv, plaintext);
        tun_write(session->tun_fd, (char *)plaintext, plain_len);
    }

    return NULL;
}

void *vpn_server_handle_client(void *arg) {
    int client_fd = *((int *)arg);
    free(arg);

    unsigned char aes_key[32];

    // Charger clé privée serveur (EVP_PKEY *)
    EVP_PKEY *pkey = crypto_load_rsa_key("keys/server_private.key", 0);
    if (!pkey) {
        logger_error("Chargement clé privée serveur échoué");
        close(client_fd);
        return NULL;
    }

int ret = crypto_receive_key(client_fd, aes_key, pkey);
EVP_PKEY_free(pkey);

if (ret < 0) {
    logger_error("Erreur réception clé AES");
    close(client_fd);
    return NULL;
}

    if (ret < 0) {
        logger_error("Erreur réception clé AES");
        close(client_fd);
        return NULL;
    }

    logger_log("Clé AES échangée avec client");

    // Création interface TUN
    char tun_name[64] = "";
    int tun_fd = tun_create(tun_name);
    if (tun_fd < 0) {
        logger_error("Erreur création TUN pour client");
        close(client_fd);
        return NULL;
    }

    logger_log("Interface TUN '%s' créée pour client", tun_name);

    // Création session client
    client_session_t *session = malloc(sizeof(client_session_t));
    if (!session) {
        logger_error("Erreur allocation mémoire session");
        close(client_fd);
        close(tun_fd);
        return NULL;
    }
    session->client_fd = client_fd;
    session->tun_fd = tun_fd;
    memcpy(session->aes_key, aes_key, 32);

    // Lancer les threads bidirectionnels
    pthread_t t1, t2;
    pthread_create(&t1, NULL, client_to_tun, session);
    pthread_create(&t2, NULL, tun_to_client, session);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    close(client_fd);
    close(tun_fd);
    free(session);

    return NULL;
}



int vpn_server_start(const char *config_path) {
    vpn_config_t config;

    if (config_load(config_path, &config) < 0) {
        logger_error("Erreur chargement config serveur");
        return -1;
    }

    // Initialiser crypto
    crypto_init();

    int sockfd = network_server_socket(config.server_ip, config.server_port);
    if (sockfd < 0) {
        logger_error("Échec ouverture socket serveur");
        return -1;
    }

    logger_log("Serveur en écoute sur %s:%d", config.server_ip, config.server_port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));
        if (!client_fd) {
            logger_error("Erreur allocation mémoire client_fd");
            continue;
        }

        *client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_fd < 0) {
            logger_error("Échec accept()");
            free(client_fd);
            continue;
        }

        pthread_t thread;
        pthread_create(&thread, NULL, vpn_server_handle_client, client_fd);
        pthread_detach(thread);
    }

    close(sockfd);
    return 0;
}
