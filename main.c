#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include <event2/event.h>

#include "config.h"
#include "cmdopt.h"
#include "logger.h"
#include "broker.h"
#include "database.h"
#include "notification.h"
#include "channel.h"
#include "dispatch.h"

enum main_flags {
    MAIN_FLAGS_NONE,
    MAIN_FLAGS_HELP = 1 << 0,
    MAIN_FLAGS_FOREGROUND = 1 << 1
};

static enum main_flags main_flags = MAIN_FLAGS_NONE;
static struct event_base *main_event_base = NULL;

static void main_foreground(void);
static void main_background(void);
static void main_event_log(int severity, char const *msg);
static void main_cleanup(void);

int main(int argc, char *argv[]) {
    cmdopt_register('h', "Show help and exit", MAIN_FLAGS_HELP, (int *) &main_flags, NULL);
    cmdopt_register('f', "Stay in the foreground and log to standard error", MAIN_FLAGS_FOREGROUND, (int *) &main_flags, NULL);
    database_cmdopt();
    broker_cmdopt();
    channel_cmdopt();
    dispatch_cmdopt();
    logger_cmdopt();
    cmdopt_parse(argc, argv);
    if (main_flags & MAIN_FLAGS_HELP) cmdopt_help(argv[0], EXIT_SUCCESS);
    atexit(main_cleanup);
    event_set_log_callback(main_event_log);
    main_event_base = event_base_new();
    if (!main_event_base) {
        perror("Unable to initialize libevent");
        exit(EXIT_FAILURE);
    }
    database_init();
    broker_init(main_event_base);
    channel_init(main_event_base);
    dispatch_init(main_event_base);
    logger_init(main_event_base, main_flags & MAIN_FLAGS_FOREGROUND);
    if (main_flags & MAIN_FLAGS_FOREGROUND) main_foreground();
    else main_background();
    logger_report(CONFIG_PRETTY_NAME " initialized successfully");
    event_base_dispatch(main_event_base);
    logger_report("Terminated");
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
    event_reinit(main_event_base);
}

static void main_event_log(int severity, char const *msg) {
    (void) severity;
    (void) msg;
}

static void main_cleanup(void) {
    if (main_event_base) event_base_free(main_event_base);
    libevent_global_shutdown();
}
