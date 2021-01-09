#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/wait.h>

#include "config.h"
#include "cmdopt.h"

enum main_flags {
    MAIN_FLAGS_NONE,
    MAIN_FLAGS_HELP = 1 << 0,
    MAIN_FLAGS_FOREGROUND = 1 << 1
};

static enum main_flags main_flags = MAIN_FLAGS_NONE;

static void main_foreground(void);
static void main_background(void);

int main(int argc, char *argv[]) {
    cmdopt_register('h', "Show help and exit", MAIN_FLAGS_HELP, (int *) &main_flags, NULL);
    cmdopt_register('f', "Stay in the foreground and log to standard error", MAIN_FLAGS_FOREGROUND, (int *) &main_flags, NULL);
    cmdopt_parse(argc, argv);
    if (main_flags & MAIN_FLAGS_HELP) cmdopt_help(argv[0], EXIT_SUCCESS);
    if (main_flags & MAIN_FLAGS_FOREGROUND) main_foreground();
    else main_background();
    syslog(LOG_INFO, CONFIG_PRETTY_NAME " initialized successfully");
    syslog(LOG_INFO, CONFIG_PRETTY_NAME " terminating gracefully");
    return EXIT_SUCCESS;
}

static void main_foreground(void) {
    if (!freopen("/dev/null", "r", stdin)) {
        perror("Unable to redirect the standard input to /dev/null");
        exit(EXIT_FAILURE);
    }
    if (!freopen("/dev/null", "a", stdout)) {
        perror("Unable to redirect the standard output to /dev/null");
        exit(EXIT_FAILURE);
    }
    openlog(CONFIG_FILESYSTEM_NAME, LOG_PERROR | LOG_PID, LOG_DAEMON);
    atexit(closelog);
}

static void main_background(void) {
    if (!freopen("/dev/null", "r", stdin)) {
        perror("Unable to redirect the standard input to /dev/null");
        exit(EXIT_FAILURE);
    }
    if (!freopen("/dev/null", "a", stdout)) {
        perror("Unable to redirect the standard output to /dev/null");
        exit(EXIT_FAILURE);
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("Unable to spawn a child process");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        int status;
        wait(&status);
        if (!WIFEXITED(status)) exit(EXIT_FAILURE);
        exit(WEXITSTATUS(status));
    }
    setsid();
    pid = fork();
    if (pid < 0) {
        perror("Unable to spawn a child process");
        exit(EXIT_FAILURE);
    }
    if (!freopen("/dev/null", "a", stderr)) {
        perror("Unable to redirect the standard error to /dev/null");
        exit(EXIT_FAILURE);
    }
    openlog(CONFIG_FILESYSTEM_NAME, LOG_PID, LOG_DAEMON);
    atexit(closelog);
}
