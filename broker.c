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
#include "registration.h"
#include "request.h"

#define BROKER_HOST "localhost"
#define BROKER_REGISTRATION_PORT "7734"
#define BROKER_REQUEST_PORT "7874"
#define BROKER_RECVBUF 8192

static char const *broker_host = BROKER_HOST;
static char const *broker_registration_port = BROKER_REGISTRATION_PORT;
static char const *broker_request_port = BROKER_REQUEST_PORT;
static struct event_base *broker_event_base;
static struct event **broker_event_list = NULL;
static size_t broker_event_count = 0;
static struct event *broker_event_sigterm;

static void broker_event_registration_handler(int sd, short events, void *arg);
static void broker_event_request_handler(int sd, short events, void *arg);
static void broker_event_signal_handler(int sd, short events, void *arg);
static int broker_socket(struct addrinfo *addrinfo, unsigned long port, event_callback_fn handler);
static void broker_cleanup(void);

void broker_cmdopt(void) {
    cmdopt_register('l', "Local address to listen on", 0, NULL, &broker_host);
    cmdopt_register('g', "Group device registration UDP port", 0, NULL, &broker_registration_port);
    cmdopt_register('n', "Notification request UDP port", 0, NULL, &broker_request_port);
}

void broker_init(struct event_base *base) {
    broker_event_base = base;
    struct addrinfo addrinfo_hint = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP, .ai_flags = AI_ADDRCONFIG};
    struct addrinfo *addrinfo_list;
    int status = getaddrinfo(broker_host, NULL, &addrinfo_hint, &addrinfo_list);
    switch (status) {
        case 0:
            break;
        case EAI_SYSTEM:
        case EAI_MEMORY:
            perror("Unable to resolve local address and service");
            goto addrinfo;
        default:
            fprintf(stderr, "Failed to resolve local address\n");
            goto addrinfo;
    }
    if (!addrinfo_list) {
        fprintf(stderr, "Address and service resolution returned no data\n");
        goto addrinfo;
    }
    unsigned long registration_port = strtoul(broker_registration_port, NULL, 10);
    unsigned long request_port = strtoul(broker_request_port, NULL, 10);
    atexit(broker_cleanup);
    for (struct addrinfo *current = addrinfo_list; current; current = current->ai_next) {
        if (broker_socket(current, registration_port, broker_event_registration_handler) < 0) goto socket;
        if (broker_socket(current, request_port, broker_event_request_handler) < 0) goto socket;
    }
    broker_event_sigterm = evsignal_new(base, SIGTERM, broker_event_signal_handler, NULL);
    if (!broker_event_sigterm) {
        perror("Unable to create an event for a signal handler");
        goto event;
    }
    if (event_add(broker_event_sigterm, NULL) < 0) {
        perror("Unable to register a signal event");
        goto reg;
    }
    freeaddrinfo(addrinfo_list);
    return;
reg:
event:
socket:
    freeaddrinfo(addrinfo_list);
addrinfo:
    exit(EXIT_FAILURE);
}

static void broker_event_registration_handler(evutil_socket_t sd, short events, void *arg) {
    (void) events;
    (void) arg;
    char buf[BROKER_RECVBUF];
    ssize_t count = recv(sd, buf, sizeof buf, 0);
    if (count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        syslog(LOG_ERR, "Aborting execution due to an error listening to a local socket: %m");
        exit(EXIT_FAILURE);
    }
    syslog(LOG_DEBUG, "Received a packet with a %zd byte registration request", count);
    registration_process(buf, count);
}

static void broker_event_request_handler(evutil_socket_t sd, short events, void *arg) {
    (void) events;
    (void) arg;
    char buf[BROKER_RECVBUF];
    ssize_t count = recv(sd, buf, sizeof buf, 0);
    if (count < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        syslog(LOG_ERR, "Aborting execution due to an error listening to a local socket: %m");
        exit(EXIT_FAILURE);
    }
    syslog(LOG_DEBUG, "Received a packet with a %zd byte notification request", count);
    request_process(buf, count);
}

static void broker_event_signal_handler(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    (void) arg;
    event_del(broker_event_sigterm);
    for (size_t index = 0; index < broker_event_count; ++ index) event_del(broker_event_list[index]);
}

static int broker_socket(struct addrinfo *addrinfo, unsigned long port, event_callback_fn handler) {
    int sd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (sd < 0) {
        perror("Unable to create a socket");
        return -1;
    }
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (int[]) {BROKER_RECVBUF}, sizeof (int)) < 0) {
        perror("Unable to change the receive buffer size on a socket");
        goto config;
    }
    if (addrinfo->ai_family == AF_INET) ((struct sockaddr_in *) addrinfo->ai_addr)->sin_port = htons(port);
    else if (addrinfo->ai_family == AF_INET6) ((struct sockaddr_in6 *) addrinfo->ai_addr)->sin6_port = htons(port);
    if (bind(sd, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0) {
        perror("Unable to bind a socket");
        goto config;
    }
    int flags = fcntl(sd, F_GETFL);
    if (flags < 0) {
        perror("Unable to obtain the flags from a socket");
        goto config;
    }
    flags |= O_NONBLOCK;
    if (fcntl(sd, F_SETFL, flags) < 0) {
        perror("Unable to set the non-blocking flag on a socket");
        goto config;
    }
    struct event *event = event_new(broker_event_base, sd, EV_READ | EV_PERSIST, handler, NULL);
    if (!event) {
        perror("Unable to create an event");
        goto event;
    }
    if (event_add(event, NULL) < 0) {
        perror("Unable to register an event");
        goto reg;
    }
    struct event **event_list = realloc(broker_event_list, (broker_event_count + 1) * sizeof *event_list);
    if (!event_list) {
        perror("Unable to reallocate memory for an event array");
        goto list;
    }
    event_list[broker_event_count ++] = event;
    broker_event_list = event_list;
    return 0;
list:
reg:
    event_free(event);
event:
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
