#include "tun.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdlib.h>

int tun_create(char *dev_name) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Erreur ouverture /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // Interface TUN sans protocole additionnel

    if (*dev_name)
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("Erreur ioctl TUNSETIFF");
        close(fd);
        return -1;
    }

    strcpy(dev_name, ifr.ifr_name);
    return fd;
}

int tun_read(int tun_fd, char *buffer, int len) {
    return read(tun_fd, buffer, len);
}

int tun_write(int tun_fd, char *buffer, int len) {
    return write(tun_fd, buffer, len);
}
