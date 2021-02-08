#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include "config.h"
#include "transport.h"
#include "cmdopt.h"

enum transport_ssl_status {
    TRANSPORT_SSL_STATUS_SUCCESS,
    TRANSPORT_SSL_STATUS_CLOSE,
    TRANSPORT_SSL_STATUS_REPEAT,
    TRANSPORT_SSL_STATUS_ERROR
};

struct transport {
    enum {
        TRANSPORT_STATE_DISCONNECTED,
        TRANSPORT_STATE_CONNECTING,
        TRANSPORT_STATE_CONNECTED,
        TRANSPORT_STATE_DISCONNECTING
    } state;
    int socket;
    SSL *ssl;
    struct event *event_read, *event_write, *event_retry;
    size_t delay_index;
    struct evutil_addrinfo *addrinfo;
    struct evdns_getaddrinfo_request *resolver;
    void *arg;
    transport_handler_t handler;
    transport_want_t want_read, want_write;
    char const *error;
    char addrstr[INET_ADDRSTRLEN >= INET6_ADDRSTRLEN ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN];
};

static char const *transport_server = NULL;
static char const *transport_port = NULL;
static char const *transport_cert_path = CONFIG_CERT_PATH;
static char const *transport_key_path = CONFIG_KEY_PATH;
static SSL_CTX *transport_ssl_ctx = NULL;
static struct event_base *transport_event_base = NULL;
static struct evdns_base *transport_evdns_base = NULL;
static struct event *transport_event_sigterm = NULL;
static unsigned const transport_delay[] = {1, 2, 5, 10, 15, 20, 30, 60};

static void transport_resolve(struct transport *transport);
static void transport_connect(struct transport *transport);
static void transport_reset(struct transport *transport);
static void transport_retry(struct transport *transport);
static void transport_evdns_on_resolve(int result, struct evutil_addrinfo *res, void *arg);
static void transport_event_on_socket_action(evutil_socket_t sd, short events, void *arg);
static void transport_event_on_retry(evutil_socket_t sd, short events, void *arg);
static void transport_event_on_signal(evutil_socket_t sd, short events, void *arg);
static void transport_ssl_on_state_info(SSL const *ssl, int where, int ret);
static enum transport_ssl_status transport_ssl_handle_status(SSL *ssl, int status);
static int transport_ssl_verify_cert(int ok, X509_STORE_CTX *x509_store_ctx);
static void transport_cleanup(void);

void transport_cmdopt(void) {
    cmdopt_register('c', "Certificate file path", 0, NULL, &transport_cert_path);
    cmdopt_register('k', "Key file path", 0, NULL, &transport_key_path);
}

void transport_init(struct event_base *base, char const *host, char const *port) {
    transport_server = host;
    transport_port = port;
    atexit(transport_cleanup);
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) != 1) {
        fprintf(stderr, "Unable to initialize OpenSSL\n");
        exit(EXIT_FAILURE);
    }
    transport_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!transport_ssl_ctx) {
        fprintf(stderr, "Unable to create an OpenSSL context object: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(transport_ssl_ctx, transport_cert_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Unable to load the certificate file: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(transport_ssl_ctx, transport_key_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Unable to load the key file: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_set_default_verify_paths(transport_ssl_ctx) != 1) {
        fprintf(stderr, "Unable to set the default certificate authority paths: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(transport_ssl_ctx, SSL_VERIFY_PEER, transport_ssl_verify_cert);
    SSL_CTX_set_info_callback(transport_ssl_ctx, transport_ssl_on_state_info);
    transport_evdns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS | EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    if (!transport_evdns_base) {
        perror("Unable to initialize the asynchronous DNS resolver");
        exit(EXIT_FAILURE);
    }
    transport_event_sigterm = evsignal_new(base, SIGTERM, transport_event_on_signal, NULL);
    if (!transport_event_sigterm) {
        perror("Unable to register a signal event");
        exit(EXIT_FAILURE);
    }
    if (event_add(transport_event_sigterm, NULL) < 0) {
        perror("Unable to add a signal event to the pendign set");
        exit(EXIT_FAILURE);
    }
    transport_event_base = base;
    struct sigaction action = {.sa_handler = SIG_IGN};
    sigemptyset(&action.sa_mask);
    sigaction(SIGPIPE, &action, NULL);
}

transport_t *transport_start(transport_handler_t handler, transport_want_t want_read, transport_want_t want_write, void *arg) {
    struct transport *transport = malloc(sizeof *transport);
    if (!transport) return NULL;
    struct event *event_retry = evtimer_new(transport_event_base, transport_event_on_retry, transport);
    if (!event_retry) goto event_retry;
    SSL *ssl = SSL_new(transport_ssl_ctx);
    if (!ssl) goto ssl;
    if (SSL_set1_host(ssl, transport_server) != 1 || SSL_set_ex_data(ssl, CRYPTO_EX_INDEX_APP, transport) != 1) goto ssl_setup;
    *transport = (struct transport) {.socket = -1, .ssl = ssl, .event_retry = event_retry, .handler = handler, .want_read = want_read, .want_write = want_write, .arg = arg};
    transport_resolve(transport);
    return transport;
ssl_setup:
    SSL_free(ssl);
ssl:
    event_free(event_retry);
event_retry:
    free(transport);
    return NULL;
}

int transport_read(transport_t *transport, char *buf, size_t len, size_t *count) {
    enum transport_ssl_status status = transport_ssl_handle_status(transport->ssl, SSL_read_ex(transport->ssl, buf, len, count));
    if (status == TRANSPORT_SSL_STATUS_ERROR) {
        transport->state = TRANSPORT_STATE_DISCONNECTING;
        syslog(LOG_WARNING, "Disconnecting from %s due to a read error: %s", transport->addrstr, transport->error);
        return -1;
    }
    return status != TRANSPORT_SSL_STATUS_REPEAT;
}

int transport_write(transport_t *transport, char const *buf, size_t len, size_t *count) {
    enum transport_ssl_status status = transport_ssl_handle_status(transport->ssl, SSL_write_ex(transport->ssl, buf, len, count));
    if (status == TRANSPORT_SSL_STATUS_ERROR) {
        transport->state = TRANSPORT_STATE_DISCONNECTING;
        syslog(LOG_WARNING, "Disconnecting from %s due to a write error: %s", transport->addrstr, transport->error);
        return -1;
    }
    return status != TRANSPORT_SSL_STATUS_REPEAT;
}

void transport_activate(transport_t *transport) {
    event_add(transport->event_read, NULL);
    event_add(transport->event_write, NULL);
}

void transport_cancel(transport_t *transport) {
    transport_reset(transport);
    if (transport->resolver) evdns_getaddrinfo_cancel(transport->resolver);
    event_free(transport->event_retry);
    if (transport->addrinfo) evutil_freeaddrinfo(transport->addrinfo);
    transport->handler(TRANSPORT_EVENT_CANCELLED, transport->arg);
    free(transport);
}

static void transport_resolve(struct transport *transport) {
    struct evutil_addrinfo hint = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP, .ai_flags = EVUTIL_AI_NUMERICSERV | EVUTIL_AI_ADDRCONFIG};
    syslog(LOG_INFO, "Resolving %s", transport_server);
    transport->resolver = evdns_getaddrinfo(transport_evdns_base, transport_server, transport_port, &hint, transport_evdns_on_resolve, transport);
}

static void transport_connect(struct transport *transport) {
    syslog(LOG_INFO, "Connecting to %s [%s] on port %s", transport_server, transport->addrstr, transport_port);
    int sd = socket(transport->addrinfo->ai_family, transport->addrinfo->ai_socktype, transport->addrinfo->ai_protocol);
    if (sd < 0) {
        syslog(LOG_WARNING, "Aborting the connection to %s due to a socket error: %m", transport->addrstr);
        goto socket;
    }
    int flags = fcntl(sd, F_GETFL);
    if (flags < 0) {
        syslog(LOG_WARNING, "Aborting the connection to %s due to an error extracting flags from the socket: %m", transport->addrstr);
        goto flags;
    }
    if (fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
        syslog(LOG_WARNING, "Aborting the connection to %s due to an error setting flags on the socket: %m", transport->addrstr);
        goto flags;
    }
    struct event *event_read = event_new(transport_event_base, sd, EV_READ, transport_event_on_socket_action, transport);
    if (!event_read) {
        syslog(LOG_WARNING, "Aborting the connection to %s due to an event registration error: %m", transport->addrstr);
        goto event_read;
    }
    struct event *event_write = event_new(transport_event_base, sd, EV_WRITE, transport_event_on_socket_action, transport);
    if (!event_write) {
        syslog(LOG_WARNING, "Aborting the connection to %s due to an event registration error: %m", transport->addrstr);
        goto event_write;
    }
    if (event_add(event_write, NULL) < 0) {
        syslog(LOG_NOTICE, "Aborting the connection to %s due to an error adding an event to the pending set: %m", transport->addrstr);
        goto schedule;
    }
    if (SSL_set_fd(transport->ssl, sd) != 1) {
        syslog(LOG_WARNING, "Aborting the connection to %s due to an error assigning the socket to OpenSSL: %s", transport->addrstr, ERR_reason_error_string(ERR_get_error()));
        goto ssl;
    }
    if (connect(sd, transport->addrinfo->ai_addr, transport->addrinfo->ai_addrlen) < 0 && errno != EINPROGRESS) {
        syslog(LOG_WARNING, "Aborting the connection to %s due to a socket error: %m", transport->addrstr);
        goto connect;
    }
    transport->socket = sd;
    transport->event_read = event_read;
    transport->event_write = event_write;
    transport->state = TRANSPORT_STATE_CONNECTING;
    return;
connect:
ssl:
schedule:
    event_free(event_write);
event_write:
    event_free(event_read);
event_read:
flags:
    close(sd);
socket:
    transport_retry(transport);
}

static void transport_reset(struct transport *transport) {
    if (transport->event_read) event_free(transport->event_read);
    transport->event_read = NULL;
    if (transport->event_write) event_free(transport->event_write);
    transport->event_write = NULL;
    SSL_clear(transport->ssl);
    if (transport->socket >= 0) {
        close(transport->socket);
        transport->socket = -1;
    }
    transport->error = NULL;
    transport->state = TRANSPORT_STATE_DISCONNECTED;
}

static void transport_retry(struct transport *transport) {
    struct timeval timeval = {.tv_sec = transport_delay[transport->delay_index] * 60, .tv_usec = 0};
    if (transport->delay_index < sizeof transport_delay - 1) ++ transport->delay_index;
    if (event_add(transport->event_retry, &timeval) < 0) {
        if (!*transport->addrstr) syslog(LOG_WARNING, "Aborting the resolution of %s due to an error adding an event to the pending set: %m", transport_server);
        else syslog(LOG_WARNING, "Aborting the connection to %s due to an error adding an event to the pending set: %m", transport->addrstr);
        transport_cancel(transport);
    }
}

static void transport_evdns_on_resolve(int result, struct evutil_addrinfo *res, void *arg) {
    struct transport *transport = arg;
    transport->resolver = NULL;
    switch (result) {
        case 0:
        case EVUTIL_EAI_NODATA:
            break;
        case EVUTIL_EAI_AGAIN:
            syslog(LOG_NOTICE, "Retrying resolving %s in a while due to a temporary name-server error", transport_server);
            transport_retry(transport);
            return;
        case EVUTIL_EAI_FAIL:
            syslog(LOG_NOTICE, "Retrying the resolution of %s in a while due to a name-server error", transport_server);
            transport_retry(transport);
            return;
        case EVUTIL_EAI_MEMORY:
            syslog(LOG_WARNING, "Retrying the resolution of %s in a while due to insufficient memory", transport_server);
            transport_retry(transport);
            return;
        case EVUTIL_EAI_NONAME:
            syslog(LOG_WARNING, "Aborting the connection to %s because the host was not found", transport_server);
            transport_cancel(transport);
            return;
        case EVUTIL_EAI_SYSTEM:
            syslog(LOG_WARNING, "Retrying the resolution of %s in a while due to a system error: %m");
            transport_retry(transport);
            return;
        case EVUTIL_EAI_CANCEL:
            syslog(LOG_INFO, "Aborting the resolution of %s", transport_server);
            return;
        default:
            syslog(LOG_ERR, "Aborting execution because the resolution of %s failed with to an unknown reason", transport_server);
            abort();
    }
    if (!res) {
        syslog(LOG_WARNING, "Aborting the connection to %s because this domain-name is not associated with an IPv4 or IPv6 address", transport_server);
        transport_cancel(transport);
        return;
    }
    transport->addrinfo = res;
    if (res->ai_next) evutil_freeaddrinfo(res->ai_next);
    res->ai_next = NULL;
    switch (res->ai_family) {
        case AF_INET:;
            struct sockaddr_in *inaddr = (struct sockaddr_in *) res->ai_addr;
            inet_ntop(AF_INET, &inaddr->sin_addr, transport->addrstr, sizeof transport->addrstr);
            break;
        case AF_INET6:;
            struct sockaddr_in6 *in6addr = (struct sockaddr_in6 *) res->ai_addr;
            inet_ntop(AF_INET6, &in6addr->sin6_addr, transport->addrstr, sizeof transport->addrstr);
            break;
        default:
            strncpy(transport->addrstr, "unknown", sizeof transport->addrstr);
    }
    transport_connect(transport);
}

static void transport_event_on_socket_action(evutil_socket_t sd, short events, void *arg) {
    struct transport *transport = arg;
    int error;
    if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, (socklen_t[]) {sizeof error}) < 0) {
        syslog(LOG_ERR, "Aborting execution due to an error extracting status information from a socket: %m");
        abort();
    }
    if (error) {
        syslog(LOG_NOTICE, "Aborting the connection to %s due to a socket error: %m", transport->addrstr);
        transport_cancel(transport);
        return;
    }
    if (transport->state == TRANSPORT_STATE_CONNECTING) {
        if (SSL_in_before(transport->ssl)) syslog(LOG_INFO, "Negotiating a TLS session with %s", transport->addrstr);
        enum transport_ssl_status status = transport_ssl_handle_status(transport->ssl, SSL_connect(transport->ssl));
        switch (status) {
            case TRANSPORT_SSL_STATUS_SUCCESS:
                break;
            case TRANSPORT_SSL_STATUS_REPEAT:
                return;
            case TRANSPORT_SSL_STATUS_CLOSE:
                syslog(LOG_NOTICE, "Aborting the connection to %s because the server disconnected abruptly", transport->addrstr);
                transport_cancel(transport);
                return;
            case TRANSPORT_SSL_STATUS_ERROR:
                syslog(LOG_NOTICE, "Aborting the connection to %s due to an error negotiating a TLS session: %s", transport->addrstr, transport->error);
                transport_cancel(transport);
                return;
        }
        transport->state = TRANSPORT_STATE_CONNECTED;
        transport->handler(TRANSPORT_EVENT_CONNECTED, transport->arg);
        transport->delay_index = 0;
        return;
    }
    if (transport->state == TRANSPORT_STATE_CONNECTED) {
        if (events & EV_READ && transport->want_read(transport->arg)) transport->handler(TRANSPORT_EVENT_READABLE, transport->arg);
        if (events & EV_WRITE && transport->want_write(transport->arg)) transport->handler(TRANSPORT_EVENT_WRITABLE, transport->arg);
        if (transport->want_read(transport->arg) && event_add(transport->event_read, NULL) < 0) {
            syslog(LOG_WARNING, "Aborting the connection to %s due to an error adding an event to the pending set: %m", transport->addrstr);
            transport_cancel(transport);
            return;
        }
        if (transport->want_write(transport->arg) && event_add(transport->event_write, NULL) < 0) {
            syslog(LOG_WARNING, "Aborting the connection to %s due to an error adding an event to the pending set: %m", transport->addrstr);
            transport_cancel(transport);
            return;
        }
    }
    if (transport->state == TRANSPORT_STATE_CONNECTED && !transport->want_read(transport->arg) && !transport->want_write(transport->arg)) {
        transport->state = TRANSPORT_STATE_DISCONNECTING;
        transport->handler(TRANSPORT_EVENT_DISCONNECTED, transport->arg);
    }
    if (transport->state == TRANSPORT_STATE_DISCONNECTING) {
        enum transport_ssl_status status = transport_ssl_handle_status(transport->ssl, SSL_shutdown(transport->ssl));
        switch (status) {
            case TRANSPORT_SSL_STATUS_REPEAT:
                return;
            case TRANSPORT_SSL_STATUS_ERROR:
                syslog(LOG_NOTICE, "Disconnecting from %s abruptly due to an error shutting down the TLS connection gracefully: %s", transport->addrstr, transport->error);
                transport_cancel(transport);
                return;
            default:
                break;
        }
        SSL_clear(transport->ssl);
        syslog(LOG_INFO, "Disconnected from %s gracefully", transport->addrstr);
        transport_cancel(transport);
    }
}

static void transport_event_on_retry(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    struct transport *transport = arg;
    if (transport->addrinfo) transport_connect(transport);
    else transport_resolve(transport);
}

static void transport_event_on_signal(evutil_socket_t sd, short events, void *arg) {
    (void) events;
    (void) arg;
    switch (sd) {
        case SIGTERM:
            event_del(transport_event_sigterm);
            evdns_base_free(transport_evdns_base, 1);
            transport_evdns_base = NULL;
    }
}

static void transport_ssl_on_state_info(SSL const *ssl, int where, int ret) {
    if (~where & SSL_CB_READ_ALERT) return;
    char const *alert = SSL_alert_desc_string(ret);
    if (alert[0] == 'C' && alert[1] == 'N') return;
    struct transport *transport = SSL_get_ex_data(ssl, CRYPTO_EX_INDEX_APP);
    syslog(LOG_INFO, "Received a TLS alert from %s: %s", transport->addrstr, SSL_alert_desc_string_long(ret));
}

static enum transport_ssl_status transport_ssl_handle_status(SSL *ssl, int status) {
    struct transport *transport = SSL_get_ex_data(ssl, CRYPTO_EX_INDEX_APP);
    switch (SSL_get_error(ssl, status)) {
        case SSL_ERROR_NONE:
            return TRANSPORT_SSL_STATUS_SUCCESS;
        case SSL_ERROR_ZERO_RETURN:
            return TRANSPORT_SSL_STATUS_CLOSE;
        case SSL_ERROR_WANT_READ:
            if (event_add(transport->event_read, NULL) < 0) {
                transport->error = strerror(errno);
                return TRANSPORT_SSL_STATUS_ERROR;
            }
            return TRANSPORT_SSL_STATUS_REPEAT;
        case SSL_ERROR_WANT_WRITE:
            if (event_add(transport->event_write, NULL) < 0) {
                transport->error = strerror(errno);
                return TRANSPORT_SSL_STATUS_ERROR;
            }
            return TRANSPORT_SSL_STATUS_REPEAT;
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            if (ERR_peek_error()) transport->error = ERR_reason_error_string(ERR_get_error());
            else if (errno) transport->error = strerror(errno);
            else {
                transport->error = "Server disconnected unexpectedly";
                return TRANSPORT_SSL_STATUS_CLOSE;
            }
            return TRANSPORT_SSL_STATUS_ERROR;
    }
    syslog(LOG_ERR, "Unexpected error code from OpenSSL");
    abort();
    return TRANSPORT_SSL_STATUS_ERROR;
}

static int transport_ssl_verify_cert(int ok, X509_STORE_CTX *x509_store_ctx) {
    int err = X509_STORE_CTX_get_error(x509_store_ctx);
    if (!ok) syslog(LOG_WARNING, "Certificate validation failed: %s", X509_verify_cert_error_string(err));
    return ok;
}

static void transport_cleanup(void) {
    if (transport_evdns_base) evdns_base_free(transport_evdns_base, 1);
    if (transport_event_sigterm) event_free(transport_event_sigterm);
    if (transport_ssl_ctx) SSL_CTX_free(transport_ssl_ctx);
}
