#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int config_load(const char *filepath, vpn_config_t *config_out) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("Erreur ouverture config");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), file)) {
        char key[64], value[256];
        if (sscanf(line, "%63[^=]=%255[^\n]", key, value) == 2) {
            if (strcmp(key, "tun_name") == 0) {
                strncpy(config_out->tun_name, value, sizeof(config_out->tun_name));
            } else if (strcmp(key, "server_ip") == 0) {
                strncpy(config_out->server_ip, value, sizeof(config_out->server_ip));
            } else if (strcmp(key, "server_port") == 0) {
                config_out->server_port = atoi(value);
            } else if (strcmp(key, "rsa_private_key") == 0) {
                strncpy(config_out->rsa_private_key_path, value, sizeof(config_out->rsa_private_key_path));
            } else if (strcmp(key, "rsa_public_key") == 0) {
                strncpy(config_out->rsa_public_key_path, value, sizeof(config_out->rsa_public_key_path));
            } else if (strcmp(key, "peer_public_key") == 0) {
                strncpy(config_out->peer_public_key_path, value, sizeof(config_out->peer_public_key_path));
            }
        }
    }

    fclose(file);
    return 0;
}
