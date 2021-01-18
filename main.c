#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/wait.h>

#include <event2/event.h>

#include "config.h"
#include "cmdopt.h"
#include "broker.h"

enum main_flags {
    MAIN_FLAGS_NONE,
    MAIN_FLAGS_HELP = 1 << 0,
    MAIN_FLAGS_FOREGROUND = 1 << 1
};

static enum main_flags main_flags = MAIN_FLAGS_NONE;
static struct event_base *main_event_base = NULL;

static void main_foreground(void);
static void main_background(void);
static void main_setup_runloop(void);
static void main_runloop(void);
static void main_event_log_stderr(int severity, char const *msg);
static void main_event_log_syslog(int severity, char const *msg);
static void main_cleanup(void);

int main(int argc, char *argv[]) {
    cmdopt_register('h', "Show help and exit", MAIN_FLAGS_HELP, (int *) &main_flags, NULL);
    cmdopt_register('f', "Stay in the foreground and log to standard error", MAIN_FLAGS_FOREGROUND, (int *) &main_flags, NULL);
    broker_cmdopt();
    cmdopt_parse(argc, argv);
    if (main_flags & MAIN_FLAGS_HELP) cmdopt_help(argv[0], EXIT_SUCCESS);
    main_setup_runloop();
    if (main_flags & MAIN_FLAGS_FOREGROUND) main_foreground();
    else main_background();
    syslog(LOG_INFO, CONFIG_PRETTY_NAME " initialized successfully");
    main_runloop();
    syslog(LOG_INFO, "Terminating gracefully");
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
    event_reinit(main_event_base);
    openlog(CONFIG_FILESYSTEM_NAME, LOG_PID, LOG_DAEMON);
    atexit(closelog);
}

static void main_setup_runloop(void) {
    atexit(main_cleanup);
    struct sigaction action = {.sa_handler = SIG_IGN};
    sigemptyset(&action.sa_mask);
    sigaction(SIGPIPE, &action, NULL);
    event_set_log_callback(main_event_log_stderr);
    main_event_base = event_base_new();
    if (!main_event_base) {
        perror("Unable to initialize libevent");
        exit(EXIT_FAILURE);
    }
    broker_init(main_event_base);
}

static void main_runloop(void) {
    event_set_log_callback(main_event_log_syslog);
    event_base_dispatch(main_event_base);
}

static void main_event_log_stderr(int severity, char const *msg) {
    if (severity == EVENT_LOG_ERR) fprintf(stderr, "Libevent error: %s\n", msg);
}

static void main_event_log_syslog(int severity, char const *msg) {
    switch (severity) {
        case EVENT_LOG_DEBUG:
            severity = LOG_DEBUG;
            break;
        case EVENT_LOG_MSG:
            severity = LOG_INFO;
            break;
        case EVENT_LOG_WARN:
            severity = LOG_WARNING;
            break;
        case EVENT_LOG_ERR:
            severity = LOG_ERR;
            break;
        default:
            abort();
    }
    syslog(severity, "From libevent: %s", msg);
}

static void main_cleanup(void) {
    if (main_event_base) event_base_free(main_event_base);
    libevent_global_shutdown();
}
