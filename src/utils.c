#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <utils.h>


// Lit exactement len octets, ou retourne <= 0 en cas d'erreur ou socket fermée
int recv_all(int fd, unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(fd, buf + total, len - total, 0);
        if (r <= 0) return r;  // erreur ou fermeture socket
        total += r;
    }
    return total;
}

// Envoie exactement len octets, ou retourne <= 0 en cas d'erreur
int send_all(int fd, unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int s = send(fd, buf + total, len - total, 0);
        if (s <= 0) return s;  // erreur
        total += s;
    }
    return total;
}