#ifndef UTILS_H
#define UTILS_H


int recv_all(int fd, unsigned char *buf, int len);
int send_all(int fd, unsigned char *buf, int len);

#endif