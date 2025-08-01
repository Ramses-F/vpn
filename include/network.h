#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>

// Initialise une socket serveur (TCP/UDP)
int network_server_socket(const char *ip, int port);

// Initialise une socket client vers un hôte distant
int network_client_socket(const char *ip, int port);

// Envoie des données via socket
int network_send(int sockfd, const void *data, size_t len);

// Reçoit des données via socket
int network_receive(int sockfd, void *buffer, size_t len);

#endif // NETWORK_H
