#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AES_KEYLEN 32 // 256 bits
#define AES_IVLEN 16

int crypto_init() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return 0;
}

int crypto_generate_rsa_keys(const char *private_key_file, const char *public_key_file) {
    int ret = -1;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto cleanup;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;

    // Écriture clé privée
    fp = fopen(private_key_file, "wb");
    if (!fp) goto cleanup;
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);

    // Écriture clé publique
    fp = fopen(public_key_file, "wb");
    if (!fp) goto cleanup;
    if (!PEM_write_PUBKEY(fp, pkey)) {
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);

    ret = 0; // succès

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (ret != 0) {
        ERR_print_errors_fp(stderr);
    }
    return ret;
}

EVP_PKEY *crypto_load_rsa_key(const char *file_path, int public) {
    FILE *fp = fopen(file_path, "rb");
    if (!fp) return NULL;

    EVP_PKEY *pkey = NULL;

    if (public) {
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    }

    fclose(fp);
    return pkey;
}

int crypto_encrypt_rsa(EVP_PKEY *pkey, const unsigned char *plaintext, size_t plaintext_len,
                       unsigned char *encrypted, size_t *encrypted_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Détermine la taille nécessaire de buffer chiffré
    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_len, plaintext, plaintext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, encrypted, encrypted_len, plaintext, plaintext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int crypto_decrypt_rsa(EVP_PKEY *pkey, const unsigned char *encrypted, size_t encrypted_len,
                       unsigned char *plaintext, size_t *plaintext_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Détermine la taille du buffer de sortie
    if (EVP_PKEY_decrypt(ctx, NULL, plaintext_len, encrypted, encrypted_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, plaintext, plaintext_len, encrypted, encrypted_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int crypto_encrypt_aes(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int crypto_decrypt_aes(const unsigned char *ciphertext, int ciphertext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Échange de clé RSA entre client et serveur
// Le client envoie une clé AES chiffrée avec la clé publique du serveur
int crypto_exchange_keys(int socket_fd, unsigned char *session_key_out) {
    unsigned char session_key[AES_KEYLEN];
    if (!RAND_bytes(session_key, sizeof(session_key))) {
        fprintf(stderr, "Erreur génération clé AES\n");
        return -1;
    }

    EVP_PKEY *pubkey = crypto_load_rsa_key("keys/server_public.key", 1);
    if (!pubkey) {
        fprintf(stderr, "Erreur chargement clé publique serveur\n");
        return -1;
    }

    unsigned char encrypted[512];
    size_t encrypted_len = sizeof(encrypted);

    if (crypto_encrypt_rsa(pubkey, session_key, sizeof(session_key), encrypted, &encrypted_len) != 0) {
        fprintf(stderr, "Erreur chiffrement RSA\n");
        EVP_PKEY_free(pubkey);
        return -1;
    }

    if (write(socket_fd, encrypted, encrypted_len) != (ssize_t)encrypted_len) {
        fprintf(stderr, "Erreur envoi clé chiffrée\n");
        EVP_PKEY_free(pubkey);
        return -1;
    }

    memcpy(session_key_out, session_key, AES_KEYLEN);
    EVP_PKEY_free(pubkey);
    return 0;
}

int crypto_receive_key(int socket_fd, unsigned char *session_key_out, EVP_PKEY *privkey) {
    unsigned char encrypted[512];
    ssize_t total = 0, n;
    size_t encrypted_len = 256; // taille attendue
    while (total < (ssize_t)encrypted_len) {
        n = read(socket_fd, encrypted + total, encrypted_len - total);
        if (n <= 0) {
            fprintf(stderr, "Erreur lecture clé chiffrée\n");
            return -1;
        }
        total += n;
    }

    size_t session_key_len = AES_KEYLEN;
    if (crypto_decrypt_rsa(privkey, encrypted, encrypted_len, session_key_out, &session_key_len) != 0) {
        fprintf(stderr, "Erreur déchiffrement RSA\n");
        return -1;
    }

    return (session_key_len == AES_KEYLEN) ? 0 : -1;
}

