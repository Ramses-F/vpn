#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "server.h"
#include "logger.h"

void usage(const char *progname) {
    printf("Usage : %s [client|server] <config_file>\n", progname);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *config_file = argv[2];

    logger_init("logs/vpn.log");
    logger_log("Démarrage VPN en mode %s", mode);

    int result = 0;

    if (strcmp(mode, "client") == 0) {
        result = vpn_client_start(config_file);
    } else if (strcmp(mode, "server") == 0) {
        result = vpn_server_start(config_file);
    } else {
        usage(argv[0]);
        result = 1;
    }

    logger_log("Fin du programme avec code %d", result);
    logger_close();
    return result;
}
