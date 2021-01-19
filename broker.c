#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <event2/event.h>

#include "config.h"
#include "broker.h"
#include "cmdopt.h"
#include "request.h"

#define BROKER_RECVBUF 8192

#define syslog(l, ...) syslog(l, "[Broker] " __VA_ARGS__)

static char const *broker_sockname = CONFIG_BROKER_ADDR;
static struct event **broker_event_list = NULL;
static size_t broker_event_count = 0;
static struct event *broker_event_sigterm;

static void broker_event_handler(int sd, short flags, void *data);
static int broker_parse_sockname(char *sockname, char **addr, char **service);
static int broker_socket(struct addrinfo *addrinfo);
static void broker_cleanup(void);

void broker_cmdopt(void) {
    cmdopt_register('l', "Listen for connections on the specified address and port", 0, NULL, &broker_sockname);
}

void broker_init(struct event_base *base) {
    char *sockname = strdup(broker_sockname);
    if (!sockname) {
        perror("Unable to allocate memory to parse address and service argument");
        exit(EXIT_FAILURE);
    }
    char *addr, *service;
    if (broker_parse_sockname(sockname, &addr, &service) < 0) {
        fprintf(stderr, "Failed to parse address and service argument\n");
        goto addrinfo;
    }
    struct addrinfo addrinfo_hint = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP, .ai_flags = AI_ADDRCONFIG};
    struct addrinfo *addrinfo_list;
    int status = getaddrinfo(addr, service, &addrinfo_hint, &addrinfo_list);
    switch (status) {
        case 0:
            break;
        case EAI_SYSTEM:
        case EAI_MEMORY:
            perror("Unable to resolve local address and service");
            goto addrinfo;
        default:
            fprintf(stderr, "Failed to resolve local address and service\n");
            goto addrinfo;
    }
    if (!addrinfo_list) {
        fprintf(stderr, "Address and service resolution returned no data\n");
        goto addrinfo;
    }
    atexit(broker_cleanup);
    for (struct addrinfo *current = addrinfo_list; current; current = current->ai_next) {
        int sd = broker_socket(current);
        if (sd < 0) {
            perror("Unable to listen on a UDP local socket");
            goto socket;
        }
        struct event *event = event_new(base, sd, EV_READ | EV_PERSIST, broker_event_handler, NULL);
        if (!event) {
            perror("Unable to create event");
            goto event;
        }
        if (event_add(event, NULL) < 0) {
            perror("Unable to register event");
            goto reg;
        }
        struct event **event_list = realloc(broker_event_list, (broker_event_count + 1) * sizeof *event_list);
        if (!event_list) goto reg;
        event_list[broker_event_count ++] = event;
        broker_event_list = event_list;
        continue;
    reg:
        event_free(event);
    event:
        close(sd);
        goto socket;
    }
    broker_event_sigterm = evsignal_new(base, SIGTERM, broker_event_handler, NULL);
    if (!broker_event_sigterm) {
        perror("Unable to create an event for a signal handler");
        goto socket;
    }
    if (event_add(broker_event_sigterm, NULL) < 0) {
        perror("Unable to register a signal event");
        goto socket;
    }
    freeaddrinfo(addrinfo_list);
    free(sockname);
    return;
socket:
    freeaddrinfo(addrinfo_list);
addrinfo:
    free(sockname);
    exit(EXIT_FAILURE);
}

static void broker_event_handler(evutil_socket_t sd, short flags, void *data) {
    (void) data;
    if (flags & EV_SIGNAL) {
        syslog(LOG_DEBUG, "Terminating");
        event_del(broker_event_sigterm);
        for (size_t index = 0; index < broker_event_count; ++ index) event_del(broker_event_list[index]);
        return;
    }
    char buf[BROKER_RECVBUF];
    ssize_t count = recv(sd, buf, sizeof buf, 0);
    if (count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        syslog(LOG_ERR, "Unable to read from listening UDP socket: %m");
        exit(EXIT_FAILURE);
    }
    request_process(buf, count);
}

static int broker_parse_sockname(char *sockname, char **node, char **service) {
    char *sep = strrchr(sockname, ':');
    if (!sep) return -1;
    *sep = 0;
    *service = sep + 1;
    for (char *ptr = *service; *ptr; ++ ptr) if (!isalnum(*ptr)) return -1;
    -- sep;
    char punct = '.';
    *node = sockname;
    if (*sockname == '[' && *sep == ']') {
        punct = ':';
        *node = sockname + 1;
        *(-- sep) = 0;
    }
    for (char *ptr = *node; *ptr; ++ ptr) if (!isalnum(*ptr) && *ptr != '-' && *ptr != punct) return -1;
    return 0;
}

static int broker_socket(struct addrinfo *addrinfo) {
    int sd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (sd < 0) return -1;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (int[]) {BROKER_RECVBUF}, sizeof (int)) < 0) goto config;
    if (bind(sd, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0) goto config;
    int flags = fcntl(sd, F_GETFL);
    if (flags < 0) goto config;
    flags |= O_NONBLOCK;
    if (fcntl(sd, F_SETFL, flags) < 0) goto config;
    return sd;
config:
    close(sd);
    return -1;
}

static void broker_cleanup(void) {
    if (broker_event_sigterm) event_free(broker_event_sigterm);
    for (size_t index = 0; index < broker_event_count; ++ index) {
        struct event *event = broker_event_list[index];
        int sd = event_get_fd(event);
        close(sd);
        event_free(event);
    }
}
