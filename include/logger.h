#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

// Initialise le système de logs
void logger_init(const char *filename);

// Écrit un message de log
void logger_log(const char *format, ...);

// Écrit un message d'erreur
void logger_error(const char *format, ...);

// Ferme le fichier de log
void logger_close();

#endif // LOGGER_H
