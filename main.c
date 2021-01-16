#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/wait.h>

#include "config.h"
#include "cmdopt.h"
#include "event.h"

enum main_flags {
    MAIN_FLAGS_NONE,
    MAIN_FLAGS_HELP = 1 << 0,
    MAIN_FLAGS_FOREGROUND = 1 << 1
};

static enum main_flags main_flags = MAIN_FLAGS_NONE;
static event_t *main_event_sighup = NULL;
static event_t *main_event_sigterm = NULL;

static void main_foreground(void);
static void main_background(void);
static void main_event_setup(void);
static void main_event_handler(event_t *event, siginfo_t *info, void *data);
static void main_cleanup(void);

int main(int argc, char *argv[]) {
    atexit(main_cleanup);
    cmdopt_register('h', "Show help and exit", MAIN_FLAGS_HELP, (int *) &main_flags, NULL);
    cmdopt_register('f', "Stay in the foreground and log to standard error", MAIN_FLAGS_FOREGROUND, (int *) &main_flags, NULL);
    cmdopt_parse(argc, argv);
    if (main_flags & MAIN_FLAGS_HELP) cmdopt_help(argv[0], EXIT_SUCCESS);
    if (main_flags & MAIN_FLAGS_FOREGROUND) main_foreground();
    else main_background();
    main_event_setup();
    syslog(LOG_INFO, CONFIG_PRETTY_NAME " initialized successfully");
    event_loop();
    syslog(LOG_INFO, CONFIG_PRETTY_NAME " terminated gracefully");
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
    if (!freopen("/dev/null", "r", stdin)) exit(EXIT_FAILURE);
    if (!freopen("/dev/null", "a", stdout)) exit(EXIT_FAILURE);
    if (!freopen("/dev/null", "a", stderr)) exit(EXIT_FAILURE);
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) {
        int status;
        wait(&status);
        if (!WIFEXITED(status)) exit(EXIT_FAILURE);
        exit(WEXITSTATUS(status));
    }
    setsid();
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    openlog(CONFIG_FILESYSTEM_NAME, LOG_PID, LOG_DAEMON);
    atexit(closelog);
}

static void main_event_setup(void) {
    main_event_sighup = event_subscribe(SIGHUP, main_event_handler, NULL);
    main_event_sigterm = event_subscribe(SIGTERM, main_event_handler, NULL);
    if (!main_event_sighup || !main_event_sigterm) {
        perror("Unable to add a signal handler event");
        exit(EXIT_FAILURE);
    }
}

static void main_event_handler(event_t *event, siginfo_t *info, void *data) {
    (void) event;
    (void) data;
    switch (info->si_signo) {
        case SIGHUP:
            syslog(LOG_INFO, CONFIG_PRETTY_NAME " Restarting");
            break;
        case SIGTERM:
            syslog(LOG_INFO, CONFIG_PRETTY_NAME " Terminating");
            event_release(main_event_sighup);
            main_event_sighup = NULL;
            event_release(main_event_sigterm);
            main_event_sigterm = NULL;
            break;
        default:
            abort();
    }
}

static void main_cleanup(void) {
    if (main_event_sighup) event_release(main_event_sighup);
    if (main_event_sigterm) event_release(main_event_sigterm);
}
