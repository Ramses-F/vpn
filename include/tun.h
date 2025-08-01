#ifndef TUN_H
#define TUN_H

// Crée et configure une interface TUN
// renvoie le descripteur de fichier de l'interface, ou -1 en cas d’erreur
int tun_create(char *dev_name);

// Lit un paquet depuis TUN
int tun_read(int tun_fd, char *buffer, int len);

// Écrit un paquet dans TUN
int tun_write(int tun_fd, char *buffer, int len);

#endif // TUN_H
