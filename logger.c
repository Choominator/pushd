#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include <event2/event.h>

#include "config.h"
#include "cmdopt.h"
#include "logger.h"

#define LOGGER_MESSAGE_LEN 512

enum logger_flags {
    LOGGER_FLAGS_NONE,
    LOGGER_FLAGS_FOREGROUND = 1 << 0
};

static enum logger_flags logger_flags = LOGGER_FLAGS_NONE;
static char const *logger_log_path = CONFIG_LOG_PATH;
static FILE *logger_log = NULL;
static char logger_message[LOGGER_MESSAGE_LEN];
static struct event_base *logger_event_base = NULL;

static void logger_post(char const *severity, char const *format, va_list ap);
static void logger_cleanup(void);

void logger_cmdopt(void) {
    cmdopt_register('o', "Log file path", 0, NULL, &logger_log_path);
}

void logger_init(struct event_base *base, int foreground) {
    logger_event_base = base;
    if (foreground) logger_flags |= LOGGER_FLAGS_FOREGROUND;
    atexit(logger_cleanup);
    logger_log = fopen(logger_log_path, "a");
    if (!logger_log) {
        fprintf(stderr, "Unable to open %s for appending\n", logger_log_path);
        exit(EXIT_FAILURE);
    }
}

void logger_propagate(char const *format, ...) {
    char message[sizeof logger_message];
    va_list ap;
    va_start(ap, format);
    size_t len = vsnprintf(message, sizeof message, format, ap);
    va_end(ap);
    if (*logger_message) {
        if (len < sizeof message) message[len ++] = ':';
        if (len < sizeof message) message[len ++] = ' ';
    }
    memmove(logger_message + len, logger_message, sizeof logger_message - len);
    memcpy(logger_message, message, len);
}

void logger_fail(char const *format, ...) {
    va_list ap;
    va_start(ap, format);
    logger_post("Fatal", format, ap);
    va_end(ap);
}

void logger_complain(char const *format, ...) {
    va_list ap;
    va_start(ap, format);
    logger_post("Error", format, ap);
    va_end(ap);
}

void logger_report(char const *format, ...) {
    va_list ap;
    va_start(ap, format);
    logger_post("Info", format, ap);
    va_end(ap);
}

void logger_debug(char const *format, ...) {
    va_list ap;
    va_start(ap, format);
    logger_post("Debug", format, ap);
    va_end(ap);
}

static void logger_post(char const *severity, char const *format, va_list ap) {
    if (!logger_log) return;
    struct timeval timeval;
    event_base_gettimeofday_cached(logger_event_base, &timeval);
    char strtime[32];
    strftime(strtime, sizeof strtime, "%F %T %z", localtime(&timeval.tv_sec));
    if (logger_flags & LOGGER_FLAGS_FOREGROUND) {
        va_list ap_copy;
        va_copy(ap_copy, ap);
        fprintf(stderr, "%s: ", severity);
        vfprintf(stderr, format, ap_copy);
        if (*logger_message) fprintf(stderr, ": %s", logger_message);
        fprintf(stderr, "\n");
        va_end(ap_copy);
    }
    fprintf(logger_log, "%s: %s: ", strtime, severity);
    vfprintf(logger_log, format, ap);
    if (*logger_message) fprintf(logger_log, ": %s", logger_message);
    fprintf(logger_log, "\n");
    *logger_message = 0;
}

static void logger_cleanup(void) {
    if (logger_log) fclose(logger_log);
    logger_log = NULL;
}
