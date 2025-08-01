#ifndef CONFIG_H
#define CONFIG_H

// Structure de configuration VPN
typedef struct {
    char tun_name[64];
    char server_ip[64];
    int server_port;
    char rsa_private_key_path[256];
    char rsa_public_key_path[256];
    char peer_public_key_path[256];
} vpn_config_t;

// Charge une configuration depuis un fichier .conf
int config_load(const char *filepath, vpn_config_t *config_out);

#endif // CONFIG_H
