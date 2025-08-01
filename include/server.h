#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <netinet/in.h>

// Initialise le serveur VPN
int vpn_server_start(const char *config_path);

// Gère une connexion client (thread ou process)
void *vpn_server_handle_client(void *arg);

#endif // SERVER_H
