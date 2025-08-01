#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>

// Démarre le client VPN en chargeant la configuration
int vpn_client_start(const char *config_path);

// Thread : lit depuis TUN, chiffre et envoie au serveur
void *vpn_client_handle_tun(void *arg);

// Thread : lit depuis serveur, déchiffre et injecte dans TUN
void *vpn_client_handle_server(void *arg);

#endif // CLIENT_H
