#include "logger.h"
#include <stdarg.h>
#include <time.h>
#include <string.h>

static FILE *log_file = NULL;

void logger_init(const char *filename) {
    log_file = fopen(filename, "a");
    if (!log_file) {
        perror("Erreur ouverture fichier de log");
    }
}

void logger_log(const char *format, ...) {
    if (!log_file) return;

    va_list args;
    va_start(args, format);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(log_file, "[%02d:%02d:%02d] ",
            t->tm_hour, t->tm_min, t->tm_sec);

    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");

    fflush(log_file);
    va_end(args);
}

void logger_error(const char *format, ...) {
    if (!log_file) return;

    va_list args;
    va_start(args, format);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(log_file, "[%02d:%02d:%02d] [ERREUR] ",
            t->tm_hour, t->tm_min, t->tm_sec);

    vfprintf(log_file, format, args);
    fprintf(log_file, "\n");

    fflush(log_file);
    va_end(args);
}

void logger_close() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
