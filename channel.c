#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
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
#include <nghttp2/nghttp2.h>

#include "config.h"
#include "cmdopt.h"
#include "logger.h"
#include "notification.h"
#include "channel.h"

#define CHANNEL_SERVER_HOST "api.push.apple.com"
#define CHANNEL_SERVER_HOST_SANDBOX "api.sandbox.push.apple.com"
#define CHANNEL_SERVER_PORT "443"
#define CHANNEL_SERVER_PORT_ALT "2197"
#define CHANNEL_PING_PERIOD "60"
#define CHANNEL_IDLE_TIMEOUT "24"
#define CHANNEL_RESOURCE_BASE_PATH "/3/device/"
#define CHANNEL_DEVICE_LEN 1024

#define CHANNEL_NGHTTP2_HEADER(n, v, l, f) {.name = (uint8_t *) (n), .value = (uint8_t *) (v), .namelen = sizeof (n) - 1, .valuelen = (l), .flags = (f) | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE}
#define CHANNEL_NGHTTP2_HEADER_LITERAL(n, v, f) {.name = (uint8_t *) (n), .value = (uint8_t *) (v), .namelen = sizeof n - 1, .valuelen = sizeof v - 1, .flags = (f) | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE}
#define CHANNEL_NGHTTP2_HEADER_COPY(n, v, l, f) {.name = (uint8_t *) (n), .value = (uint8_t *) (v), .namelen = sizeof (n) - 1, .valuelen = (l), .flags = (f) | NGHTTP2_NV_FLAG_NO_COPY_NAME}

enum channel_flags {
    CHANNEL_FLAGS_NONE,
    CHANNEL_FLAGS_SERVER_HOST_SANDBOX = 1 << 0,
    CHANNEL_FLAGS_SERVER_PORT_ALT = 1 << 1
};

enum channel_ssl_status {
    CHANNEL_SSL_STATUS_SUCCESS,
    CHANNEL_SSL_STATUS_CLOSE,
    CHANNEL_SSL_STATUS_REPEAT,
    CHANNEL_SSL_STATUS_ERROR
};

struct channel {
    unsigned long long id;
    enum {
        CHANNEL_STATE_DISCONNECTED,
        CHANNEL_STATE_CONNECTING,
        CHANNEL_STATE_CONNECTED,
        CHANNEL_STATE_DISCONNECTING
    } state;
    int socket;
    SSL *ssl;
    nghttp2_session *nghttp2;
    struct event *event_read, *event_write, *event_retry, *event_ping, *event_idle;
    notification_queue_t *notification_queue;
    size_t delay_index;
    struct evdns_getaddrinfo_request *resolver;
    struct channel_handlers handlers;
    void *arg;
};

static enum channel_flags channel_flags = CHANNEL_FLAGS_NONE;
static char const *channel_server_host = CHANNEL_SERVER_HOST;
static char const *channel_server_port = CHANNEL_SERVER_PORT;
static char const *channel_cert_path = CONFIG_CERT_PATH;
static char const *channel_key_path = CONFIG_KEY_PATH;
static char const *channel_ping_period = CHANNEL_PING_PERIOD;
static char const *channel_idle_timeout = CHANNEL_IDLE_TIMEOUT;
static size_t channel_server_host_len = sizeof CHANNEL_SERVER_HOST - 1;
static unsigned long long channel_id = 0;
static SSL_CTX *channel_ssl_ctx = NULL;
static struct event_base *channel_event_base = NULL;
static struct evdns_base *channel_evdns_base = NULL;
static struct event *channel_event_sigterm = NULL;
static unsigned const channel_delay[] = {1, 2, 5, 10, 15, 20, 30, 60};
static struct timeval channel_timeval_ping_period = {.tv_sec = 0, .tv_usec = 0};
static struct timeval channel_timeval_idle_timeout = {.tv_sec = 0, .tv_usec = 0};
static nghttp2_session_callbacks *channel_nghttp2_callbacks = NULL;

static void channel_resolve(struct channel *channel);
static void channel_connect(struct channel *channel, struct addrinfo const *addrinfo);
static void channel_reset(struct channel *channel);
static void channel_retry(struct channel *channel);
static void channel_action(struct channel *channel);
static void channel_on_connect(struct channel *channel);
static void channel_on_disconnect(struct channel *channel, char const *reaason, size_t len);
static void channel_evdns_on_resolve(int result, struct evutil_addrinfo *res, void *arg);
static void channel_event_on_socket_action(evutil_socket_t sd, short events, void *arg);
static void channel_event_on_retry(evutil_socket_t sd, short events, void *arg);
static void channel_event_do_ping(evutil_socket_t sd, short events, void *arg);
static void channel_event_on_idle_timeout(evutil_socket_t sd, short events, void *arg);
static void channel_event_on_signal(evutil_socket_t sd, short events, void *arg);
static void channel_ssl_on_state_info(SSL const *ssl, int where, int ret);
static enum channel_ssl_status channel_ssl_handle_status(SSL *ssl, int status);
static int channel_ssl_verify_cert(int ok, X509_STORE_CTX *x509_store_ctx);
static ssize_t channel_nghttp2_do_recv(nghttp2_session *nghttp2, uint8_t *buf, size_t len, int flags, void *arg);
static ssize_t channel_nghttp2_do_send(nghttp2_session *nghttp2, uint8_t const *buf, size_t len, int flags, void *arg);
static int channel_nghttp2_on_frame_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, void *arg);
static int channel_nghttp2_on_header_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, uint8_t const *name, size_t name_len, uint8_t const *value, size_t value_len, uint8_t flags, void *arg);
static int channel_nghttp2_on_data_recv(nghttp2_session *nghttp2, uint8_t flags, int32_t stream_id, uint8_t const *buf, size_t len, void *arg);
static int channel_nghttp2_on_stream_close(nghttp2_session *nghttp2, int32_t stream_id, uint32_t error, void *arg);
static ssize_t channel_nghttp2_do_fetch_data(nghttp2_session *nghttp2, int32_t stream_id, uint8_t *buf, size_t len, uint32_t *flags, nghttp2_data_source *source, void *arg);
static void channel_cleanup(void);

void channel_cmdopt(void) {
    cmdopt_register('s', "Connect to host " CHANNEL_SERVER_HOST_SANDBOX " instead of " CHANNEL_SERVER_HOST, CHANNEL_FLAGS_SERVER_HOST_SANDBOX, (int *) &channel_flags, NULL);
    cmdopt_register('p', "Connect to port " CHANNEL_SERVER_PORT_ALT " instead of " CHANNEL_SERVER_PORT, CHANNEL_FLAGS_SERVER_PORT_ALT, (int *) &channel_flags, NULL);
    cmdopt_register('c', "Client certificate file path", 0, NULL, &channel_cert_path);
    cmdopt_register('k', "Client key file path", 0, NULL, &channel_key_path);
    cmdopt_register('t', "Ping period in minutes (0 disables)", 0, NULL, &channel_ping_period);
    cmdopt_register('i', "Idle timeout in hours (0 disables)", 0, NULL, &channel_idle_timeout);
}

void channel_init(struct event_base *base) {
    if (channel_flags & CHANNEL_FLAGS_SERVER_HOST_SANDBOX) {
        channel_server_host = CHANNEL_SERVER_HOST_SANDBOX;
        channel_server_host_len = sizeof CHANNEL_SERVER_HOST_SANDBOX - 1;
    }
    if (channel_flags & CHANNEL_FLAGS_SERVER_PORT_ALT) channel_server_port = CHANNEL_SERVER_PORT_ALT;
    int ping_period = atoi(channel_ping_period);
    if (ping_period > 0) channel_timeval_ping_period.tv_sec = ping_period * 60;
    int idle_timeout = atoi(channel_idle_timeout);
    if (idle_timeout > 0) channel_timeval_idle_timeout.tv_sec = idle_timeout * 60 * 60;
    atexit(channel_cleanup);
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) != 1) {
        fprintf(stderr, "Unable to initialize OpenSSL: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    channel_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!channel_ssl_ctx) {
        fprintf(stderr, "Unable to create an OpenSSL context object: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_certificate_file(channel_ssl_ctx, channel_cert_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Unable to load the certificate from %s: %s\n", channel_cert_path, ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(channel_ssl_ctx, channel_key_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Unable to load the private key from %s: %s\n", channel_key_path, ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_set_default_verify_paths(channel_ssl_ctx) != 1) {
        fprintf(stderr, "Unable to set the certificate authority paths to OpenSSL's default values: %s\n", ERR_reason_error_string(ERR_get_error()));
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(channel_ssl_ctx, SSL_VERIFY_PEER, channel_ssl_verify_cert);
    SSL_CTX_set_info_callback(channel_ssl_ctx, channel_ssl_on_state_info);
    channel_evdns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS | EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    if (!channel_evdns_base) {
        perror("Unable to initialize libevent's asynchronous DNS resolver");
        exit(EXIT_FAILURE);
    }
    channel_event_sigterm = evsignal_new(base, SIGTERM, channel_event_on_signal, NULL);
    if (!channel_event_sigterm) {
        perror("Unable to create a signal event");
        exit(EXIT_FAILURE);
    }
    if (event_add(channel_event_sigterm, NULL) < 0) {
        perror("Unable to register a signal event");
        exit(EXIT_FAILURE);
    }
    int status = nghttp2_session_callbacks_new(&channel_nghttp2_callbacks);
    if (status) {
        fprintf(stderr, "Unable to initialize the nghttp2 callbacks object: %s\n", nghttp2_strerror(status));
        exit(EXIT_FAILURE);
    }
    nghttp2_session_callbacks_set_recv_callback(channel_nghttp2_callbacks, channel_nghttp2_do_recv);
    nghttp2_session_callbacks_set_send_callback(channel_nghttp2_callbacks, channel_nghttp2_do_send);
    nghttp2_session_callbacks_set_on_frame_recv_callback(channel_nghttp2_callbacks, channel_nghttp2_on_frame_recv);
    nghttp2_session_callbacks_set_on_header_callback(channel_nghttp2_callbacks, channel_nghttp2_on_header_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(channel_nghttp2_callbacks, channel_nghttp2_on_data_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(channel_nghttp2_callbacks, channel_nghttp2_on_stream_close);
    struct sigaction action = {.sa_handler = SIG_IGN};
    sigemptyset(&action.sa_mask);
    sigaction(SIGPIPE, &action, NULL);
    channel_event_base = base;
}

channel_t *channel_start(struct channel_handlers *handlers, void *arg) {
    struct channel *channel = malloc(sizeof *channel);
    if (!channel) {
        logger_propagate("Allocating memory: %s", strerror(errno));
        goto channel;
    }
    struct event *event_retry = evtimer_new(channel_event_base, channel_event_on_retry, channel);
    if (!event_retry) {
        logger_propagate("Creating a timer event handler: %s", strerror(errno));
        goto event_retry;
    }
    *channel = (struct channel) {.id = ++ channel_id, .socket = -1, .event_retry = event_retry, .handlers = *handlers, .arg = arg};
    logger_debug("Created channel #%llu", channel_id);
    channel_resolve(channel);
    return channel;
event_retry:
    free(channel);
channel:
    logger_propagate("Creating channel #%llu", ++ channel_id);
    return NULL;
}

void channel_stop(channel_t *channel) {
    if (channel->state != CHANNEL_STATE_CONNECTED) {
        channel_cancel(channel);
        return;
    }
    if (!channel->event_ping) return;
    channel_on_disconnect(channel, NULL, 0);
    int status = nghttp2_session_terminate_session(channel->nghttp2, NGHTTP2_NO_ERROR);
    if (status < 0) {
        logger_complain("Stopping channel #%llu: Shutting down the HTPP/2 session: %s", channel->id, nghttp2_strerror(status));
        channel_cancel(channel);
        return;
    }
    channel_action(channel);
    logger_debug("Stopping channel #%llu", channel->id);
}

enum channel_post_result channel_post(channel_t *channel, notification_t *notification) {
    if (channel->state != CHANNEL_STATE_CONNECTED) {
        logger_fail("Attempted to send a notification through a disconnected channel");
        abort();
    }
    enum channel_post_result ret = CHANNEL_POST_RESULT_SUCCESS;
    char const *device;
    size_t device_len;
    notification_get_device(notification, &device, &device_len);
    char path[sizeof CHANNEL_RESOURCE_BASE_PATH + CHANNEL_DEVICE_LEN];
    size_t path_len = sizeof CHANNEL_RESOURCE_BASE_PATH - 1 + device_len;
    if (path_len >= sizeof path) {
        logger_propagate("Device token too long");
        ret = CHANNEL_POST_RESULT_INVALID;
        goto device;
    }
    snprintf(path, sizeof path, CHANNEL_RESOURCE_BASE_PATH "%.*s", (int) device_len, device);
    char *type = "background", *priority = "5";
    size_t type_len = sizeof "background" - 1, priority_len = sizeof "5" - 1;
    if (notification_get_type(notification) > NOTIFICATION_TYPE_BACKGROUND) {
        type = "alert";
        type_len = sizeof "alert" - 1;
    }
    if (notification_get_type(notification) > NOTIFICATION_TYPE_NORMAL) {
        priority = "10";
        priority_len = sizeof "10" - 1;
    }
    char expiration[24];
    size_t expiration_len = snprintf(expiration, sizeof expiration, "%lld", (long long) notification_get_expiration(notification));
    char const *key;
    size_t key_len;
    notification_get_key(notification, &key, &key_len);
    nghttp2_nv headers[] = {
        CHANNEL_NGHTTP2_HEADER_LITERAL(":method", "POST", NGHTTP2_NV_FLAG_NONE),
        CHANNEL_NGHTTP2_HEADER_LITERAL(":scheme", "https", NGHTTP2_NV_FLAG_NONE),
        CHANNEL_NGHTTP2_HEADER_COPY(":path", path, path_len, NGHTTP2_NV_FLAG_NO_INDEX),
        CHANNEL_NGHTTP2_HEADER("host", channel_server_host, channel_server_host_len, NGHTTP2_NV_FLAG_NONE),
        CHANNEL_NGHTTP2_HEADER("apns-push-type", type, type_len, NGHTTP2_NV_FLAG_NONE),
        CHANNEL_NGHTTP2_HEADER_COPY("apns-expiration", expiration, expiration_len, NGHTTP2_NV_FLAG_NO_INDEX),
        CHANNEL_NGHTTP2_HEADER("apns-priority", priority, priority_len, NGHTTP2_NV_FLAG_NONE),
        CHANNEL_NGHTTP2_HEADER("apns-collapse-id", key, key_len, NGHTTP2_NV_FLAG_NO_INDEX)
    };
    size_t headers_len = sizeof headers / sizeof *headers;
    if (!key_len) -- headers_len;
    nghttp2_data_provider provider = {.source = {.ptr = notification}, .read_callback = channel_nghttp2_do_fetch_data};
    int32_t stream_id = nghttp2_submit_request(channel->nghttp2, NULL, headers, headers_len, &provider, notification);
    if (stream_id < 0) {
        if (stream_id == NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE) {
            logger_propagate("Reached the maximum number of allowed streams");
            ret = CHANNEL_POST_RESULT_BUSY;
            goto stream;
        }
        channel_cancel(channel);
        logger_propagate("Submitting HTTP/2 POST request: %s", nghttp2_strerror(stream_id));
        ret = CHANNEL_POST_RESULT_ERROR;
        goto stream;
    }
    channel_action(channel);
    notification_queue_requeue(channel->notification_queue, notification);
    logger_debug("Sending notification #%llu through channel #%llu", notification_get_id(notification), channel->id);
    return CHANNEL_POST_RESULT_SUCCESS;
stream:
device:
    logger_propagate("Sending notification #%llu through channel #%llu", notification_get_id(notification), channel->id);
    return ret;
}

void channel_cancel(channel_t *channel) {
    if (channel->state == CHANNEL_STATE_CONNECTED) channel_on_disconnect(channel, NULL, 0);
    channel->handlers.on_cancel(channel->notification_queue, channel->arg);
    if (channel->resolver) evdns_getaddrinfo_cancel(channel->resolver);
    if (channel->event_retry) event_free(channel->event_retry);
    channel_reset(channel);
    unsigned long long id = channel->id;
    free(channel);
    logger_debug("Cancelled channel #%llu", id);
}

static void channel_resolve(struct channel *channel) {
    struct evutil_addrinfo hint = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP, .ai_flags = EVUTIL_AI_NUMERICSERV | EVUTIL_AI_ADDRCONFIG};
    channel->resolver = evdns_getaddrinfo(channel_evdns_base, channel_server_host, channel_server_port, &hint, channel_evdns_on_resolve, channel);
    logger_debug("Resolving %s", channel_server_host);
}

static void channel_connect(struct channel *channel, struct addrinfo const *addrinfo) {
    char addrstr[INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN] = "Unknown";
    switch (addrinfo->ai_family) {
        case AF_INET:
            inet_ntop(AF_INET, &((struct sockaddr_in *) addrinfo->ai_addr)->sin_addr, addrstr, sizeof addrstr);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addrinfo->ai_addr)->sin6_addr, addrstr, sizeof addrstr);
            break;
    }
    int sd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (sd < 0) {
        logger_propagate("Creating a socket: %s", strerror(errno));
        goto socket;
    }
    int flags = fcntl(sd, F_GETFL);
    if (flags < 0) {
        logger_propagate("Getting flags from the socket: %s", strerror(errno));
        goto flags;
    }
    if (fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
        logger_propagate("Setting flags on the socket: %s", strerror(errno));
        goto flags;
    }
    struct event *event_read = event_new(channel_event_base, sd, EV_READ, channel_event_on_socket_action, channel);
    if (!event_read) {
        logger_propagate("Creating a read socket event handler: %s", strerror(errno));
        goto event_read;
    }
    struct event *event_write = event_new(channel_event_base, sd, EV_WRITE, channel_event_on_socket_action, channel);
    if (!event_write) {
        logger_propagate("Creating a write socket event handler: %s", strerror(errno));
        goto event_write;
    }
    struct event *event_ping = evtimer_new(channel_event_base, channel_event_do_ping, channel);
    if (!event_ping) {
        logger_propagate("Creating a ping timer event handler: %s", strerror(errno));
        goto event_ping;
    }
    struct event *event_idle = evtimer_new(channel_event_base, channel_event_on_idle_timeout, channel);
    if (!event_idle) {
        logger_propagate("Creating a idle timer event handler: %s", strerror(errno));
        goto event_idle;
    }
    SSL *ssl = SSL_new(channel_ssl_ctx);
    if (!ssl) {
        logger_propagate("Creating a TLS session handler: %s",ERR_reason_error_string(ERR_get_error()));
        goto ssl;
    }
    if (SSL_set1_host(ssl, channel_server_host) != 1 || SSL_set_ex_data(ssl, CRYPTO_EX_INDEX_APP, channel) != 1 || SSL_set_fd(ssl, sd) != 1) {
        logger_propagate("Setting up the TLS session handler: %s", ERR_reason_error_string(ERR_get_error()));
        goto ssl_setup;
    }
    nghttp2_session *nghttp2;
    int status = nghttp2_session_client_new(&nghttp2, channel_nghttp2_callbacks, channel);
    if (status < 0) {
        logger_propagate("Creating a HTTP/2 session handler: %s", nghttp2_strerror(status));
        goto nghttp2;
    }
    notification_queue_t *notification_queue = notification_queue_create();
    if (!notification_queue) goto notification_queue;
    if (event_add(event_write, NULL) < 0) {
        logger_complain("Setting the write socket event on channel #%llu to pending: %s", strerror(errno));
        goto schedule;
    }
    if (connect(sd, addrinfo->ai_addr, addrinfo->ai_addrlen) < 0 && errno != EINPROGRESS) {
        logger_propagate("Establishing the connection: %s", strerror(errno));
        goto connect;
    }
    channel->socket = sd;
    channel->event_read = event_read;
    channel->event_write = event_write;
    channel->event_ping = event_ping;
    channel->event_idle = event_idle;
    channel->ssl = ssl;
    channel->nghttp2 = nghttp2;
    channel->notification_queue = notification_queue;
    channel->state = CHANNEL_STATE_CONNECTING;
    logger_debug("Connecting to %s port %s on channel #%llu", addrstr, channel_server_port, channel->id);
    return;
connect:
schedule:
    notification_queue_destroy(notification_queue);
notification_queue:
    nghttp2_session_del(nghttp2);
nghttp2:
ssl_setup:
    SSL_free(ssl);
ssl:
    event_free(event_idle);
event_idle:
    event_free(event_ping);
event_ping:
    event_free(event_write);
event_write:
    event_free(event_read);
event_read:
flags:
    close(sd);
socket:
    logger_complain("Connecting to %s port %s on channel #%llu", addrstr, channel_server_port, channel->id);
    channel_retry(channel);
}

static void channel_reset(struct channel *channel) {
    if (channel->notification_queue) notification_queue_destroy(channel->notification_queue);
    channel->notification_queue = NULL;
    if (channel->nghttp2) nghttp2_session_del(channel->nghttp2);
    channel->nghttp2 = NULL;
    if (channel->ssl) SSL_free(channel->ssl);
    channel->ssl = NULL;
    if (channel->event_idle) event_free(channel->event_idle);
    channel->event_idle = NULL;
    if (channel->event_ping) event_free(channel->event_ping);
    channel->event_ping = NULL;
    if (channel->event_write) event_free(channel->event_write);
    channel->event_write = NULL;
    if (channel->event_read) event_free(channel->event_read);
    channel->event_read = NULL;
    if (channel->socket >= 0) close(channel->socket);
    channel->socket = -1;
    channel->state = CHANNEL_STATE_DISCONNECTED;
}

static void channel_retry(struct channel *channel) {
    if (!channel->event_retry) return;
    channel_reset(channel);
    unsigned delay = channel_delay[channel->delay_index];
    struct timeval timeval = {.tv_sec = delay * 60, .tv_usec = 0};
    if (channel->delay_index < sizeof channel_delay - 1) ++ channel->delay_index;
    if (event_add(channel->event_retry, &timeval) < 0) {
        logger_complain("Setting up a retry timer on channel #%llu: Setting the retry timer event to pending: %s", channel->id, strerror(errno));
        channel_cancel(channel);
        return;
    }
    logger_debug("Retrying the connection on channel #%llu in %u minutes", channel->id, delay);
}

static void channel_action(struct channel *channel) {
    if (nghttp2_session_want_read(channel->nghttp2) && event_add(channel->event_read, NULL) < 0) {
        channel_cancel(channel);
        logger_propagate("Setting the read socket event to pending: %s", strerror(errno));
        goto read;
    }
    if (nghttp2_session_want_write(channel->nghttp2) && event_add(channel->event_write, NULL) < 0) {
        channel_cancel(channel);
        logger_propagate("Setting the write socket event to pending: %s", strerror(errno));
        goto write;
    }
    if (!channel->event_ping) return;
    if (channel_timeval_ping_period.tv_sec && event_add(channel->event_ping, &channel_timeval_ping_period) < 0) {
        channel_cancel(channel);
        logger_propagate("Setting the ping timer event to pending: %s", strerror(errno));
        goto ping;
    }
    if (channel_timeval_idle_timeout.tv_sec && event_add(channel->event_idle, &channel_timeval_idle_timeout) < 0) {
        channel_cancel(channel);
        logger_propagate("Setting the idle timer event to pending: %s", strerror(errno));
        goto idle;
    }
    return;
idle:
ping:
write:
read:
    logger_complain("Action on channel #%llu", channel->id);
}

static void channel_on_connect(struct channel *channel) {
    if (!channel->event_retry) return;
    event_free(channel->event_retry);
    channel->event_retry = NULL;
    int status = nghttp2_submit_settings(channel->nghttp2, NGHTTP2_FLAG_NONE, NULL, 0);
    if (status < 0) {
        channel_cancel(channel);
        logger_propagate("Submitting the HTTP/2 settings frame: %s", nghttp2_strerror(status));
        goto submission;
    }
    channel_action(channel);
    channel->state = CHANNEL_STATE_CONNECTED;
    logger_debug("Connection established on channel #%llu", channel->id);
    channel->handlers.on_connect(channel->arg);
    return;
submission:
    logger_complain("Socket event on channel #%llu", channel->id);
}

static void channel_on_disconnect(struct channel *channel, char const *reason, size_t len) {
    if (!channel->event_ping) return;
    event_free(channel->event_ping);
    channel->event_ping = NULL;
    channel->handlers.on_disconnect(reason, len, channel->arg);
}

static void channel_evdns_on_resolve(int result, struct evutil_addrinfo *res, void *arg) {
    struct channel *channel = arg;
    channel->resolver = NULL;
    switch (result) {
        case 0:
        case EVUTIL_EAI_NODATA:
            break;
        case EVUTIL_EAI_AGAIN:
            channel_retry(channel);
            logger_propagate("Temporary name-server error");
            goto temporary;
        case EVUTIL_EAI_FAIL:
            channel_retry(channel);
            logger_propagate("permanent name-server error");
            goto permanent;
        case EVUTIL_EAI_NONAME:
            channel_cancel(channel);
            logger_propagate("Host not found");
            goto notfound;
        case EVUTIL_EAI_MEMORY:
            errno = ENOMEM;
        case EVUTIL_EAI_SYSTEM:
            channel_retry(channel);
            logger_propagate("%s", strerror(errno));
            goto system;
        case EVUTIL_EAI_CANCEL:
            return;
        default:
            logger_fail("Resolving the server's hostname: Unknown error");
            abort();
    }
    if (!res) {
        channel_cancel(channel);
        logger_propagate("No addresses returned");
        goto notfound;
    }
    logger_debug("Resolved %s", channel_server_host);
    channel_connect(channel, res);
    evutil_freeaddrinfo(res);
    return;
system:
notfound:
permanent:
temporary:
    logger_complain("Resolving %s", channel_server_host);
}

static void channel_event_on_socket_action(evutil_socket_t sd, short events, void *arg) {
    struct channel *channel = arg;
    int error;
    if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, (socklen_t[]) {sizeof error}) < 0) {
        logger_fail("Socket event: Getting socket error information: %s", strerror(errno));
        abort();
    }
    if (error) {
        channel_cancel(channel);
        logger_complain("Socket event on channel #%llu: %s", channel->id, strerror(error));
        return;
    }
    if (channel->state == CHANNEL_STATE_CONNECTING) {
        enum channel_ssl_status status = channel_ssl_handle_status(channel->ssl, SSL_connect(channel->ssl));
        switch (status) {
            case CHANNEL_SSL_STATUS_SUCCESS:
                break;
            case CHANNEL_SSL_STATUS_REPEAT:
                return;
            case CHANNEL_SSL_STATUS_CLOSE:
            case CHANNEL_SSL_STATUS_ERROR:
                channel_cancel(channel);
                logger_complain("Socket event on channel #%llu: Negotiating a TLS session", channel->id);
                return;
        }
        channel_on_connect(channel);
        return;
    }
    if (channel->state == CHANNEL_STATE_CONNECTED) {
        if (events & EV_READ && nghttp2_session_want_read(channel->nghttp2)) {
            int status = nghttp2_session_recv(channel->nghttp2);
            switch (status) {
                case 0:
                    break;
                case NGHTTP2_ERR_CALLBACK_FAILURE:
                    logger_complain("Socket event on channel #%llu", channel->id);
                    break;
                default:
                    logger_complain("Socket event on channel #%llu: Receiving data: %s", channel->id, nghttp2_strerror(status));
            }
            if (status < 0) {
                channel_cancel(channel);
                return;
            }
        }
        if (events & EV_WRITE && nghttp2_session_want_write(channel->nghttp2)) {
            int status = nghttp2_session_send(channel->nghttp2);
            switch (status) {
                case 0:
                    break;
                case NGHTTP2_ERR_CALLBACK_FAILURE:
                    logger_complain("Socket event on channel #%llu", channel->id);
                    break;
                default:
                    logger_complain("Socket event on channel #%llu: Sending data: %s", channel->id, nghttp2_strerror(status));
            }
            if (status < 0) {
                channel_cancel(channel);
                return;
            }
        }
        channel_action(channel);
    }
    if (channel->state == CHANNEL_STATE_CONNECTED && !nghttp2_session_want_read(channel->nghttp2) && !nghttp2_session_want_write(channel->nghttp2)) channel->state = CHANNEL_STATE_DISCONNECTING;
    if (channel->state == CHANNEL_STATE_DISCONNECTING) {
        enum channel_ssl_status status = channel_ssl_handle_status(channel->ssl, SSL_shutdown(channel->ssl));
        if (status == CHANNEL_SSL_STATUS_REPEAT) return;
        channel_cancel(channel);
    }
}

static void channel_event_on_retry(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    channel_resolve(arg);
}

static void channel_event_do_ping(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    struct channel *channel = arg;
    int status = nghttp2_submit_ping(channel->nghttp2, NGHTTP2_FLAG_NONE, NULL);
    if (status < 0) {
        channel_cancel(channel);
        logger_propagate("Sending an HTTP/2 ping frame: %s", nghttp2_strerror(status));
        goto submission;
    }
    if (event_add(channel->event_ping, &channel_timeval_ping_period) < 0) {
        channel_cancel(channel);
        logger_propagate("Setting the ping timer event to pending: %s", strerror(errno));
        goto schedule;
    }
    channel_action(channel);
    return;
schedule:
submission:
    logger_complain("Ping event on channel #%llu", channel->id);
}

static void channel_event_on_idle_timeout(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    struct channel *channel = arg;
    logger_debug("Idle timeout on channel #%llu", channel->id);
    if (channel->event_ping) channel_stop(channel);
    else channel_cancel(channel);
}

static void channel_event_on_signal(evutil_socket_t sd, short events, void *arg) {
    (void) events;
    (void) arg;
    switch (sd) {
        case SIGTERM:
            event_del(channel_event_sigterm);
            evdns_base_free(channel_evdns_base, 1);
            channel_evdns_base = NULL;
    }
}

static void channel_ssl_on_state_info(SSL const *ssl, int where, int ret) {
    if (~where & SSL_CB_READ_ALERT) return;
    char const *alert = SSL_alert_desc_string(ret);
    if (alert[0] == 'C' && alert[1] == 'N') return;
    struct channel *channel = SSL_get_ex_data(ssl, CRYPTO_EX_INDEX_APP);
    logger_complain("TLS alert on channel #%llu: %s", channel->id, SSL_alert_desc_string_long(ret));
}

static enum channel_ssl_status channel_ssl_handle_status(SSL *ssl, int status) {
    struct channel *channel = SSL_get_ex_data(ssl, CRYPTO_EX_INDEX_APP);
    switch (SSL_get_error(ssl, status)) {
        case SSL_ERROR_NONE:
            return CHANNEL_SSL_STATUS_SUCCESS;
        case SSL_ERROR_ZERO_RETURN:
            return CHANNEL_SSL_STATUS_CLOSE;
        case SSL_ERROR_WANT_READ:
            if (event_add(channel->event_read, NULL) < 0) {
                logger_propagate("Setting the read event to pending: %s", strerror(errno));
                return CHANNEL_SSL_STATUS_ERROR;
            }
            return CHANNEL_SSL_STATUS_REPEAT;
        case SSL_ERROR_WANT_WRITE:
            if (event_add(channel->event_write, NULL) < 0) {
                logger_propagate("Setting the write event to pending: %s", strerror(errno));
                return CHANNEL_SSL_STATUS_ERROR;
            }
            return CHANNEL_SSL_STATUS_REPEAT;
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            if (ERR_peek_error()) logger_propagate("%s", ERR_reason_error_string(ERR_get_error()));
            else if (errno) logger_propagate("%s", strerror(errno));
            else return CHANNEL_SSL_STATUS_CLOSE;
            return CHANNEL_SSL_STATUS_ERROR;
    }
    logger_fail("Unexpected error code from OpenSSL");
    abort();
    return CHANNEL_SSL_STATUS_ERROR;
}

static int channel_ssl_verify_cert(int ok, X509_STORE_CTX *x509_store_ctx) {
    int err = X509_STORE_CTX_get_error(x509_store_ctx);
    if (!ok) logger_propagate("X509 certificate validation failed: %s", X509_verify_cert_error_string(err));
    return ok;
}

static ssize_t channel_nghttp2_do_recv(nghttp2_session *nghttp2, uint8_t *buf, size_t len, int flags, void *arg) {
    (void) nghttp2;
    (void) flags;
    struct channel *channel = arg;
    size_t count;
    enum channel_ssl_status status = channel_ssl_handle_status(channel->ssl, SSL_read_ex(channel->ssl, (char *) buf, len, &count));
    switch (status) {
        case CHANNEL_SSL_STATUS_SUCCESS:
            break;
        case CHANNEL_SSL_STATUS_REPEAT:
            if (!count) return NGHTTP2_ERR_WOULDBLOCK;
            return count;
        case CHANNEL_SSL_STATUS_CLOSE:
            if (!count) return NGHTTP2_ERR_EOF;
            return count;
        case CHANNEL_SSL_STATUS_ERROR:
            return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return count;
}

static ssize_t channel_nghttp2_do_send(nghttp2_session *nghttp2, uint8_t const *buf, size_t len, int flags, void *arg) {
    (void) nghttp2;
    (void) flags;
    struct channel *channel = arg;
    size_t count;
    enum channel_ssl_status status = channel_ssl_handle_status(channel->ssl, SSL_write_ex(channel->ssl, (char const *) buf, len, &count));
    switch (status) {
        case CHANNEL_SSL_STATUS_SUCCESS:
            break;
        case CHANNEL_SSL_STATUS_REPEAT:
            if (!count) return NGHTTP2_ERR_WOULDBLOCK;
            return count;
        case CHANNEL_SSL_STATUS_CLOSE:
            if (!count) return len;
            return count;
        case CHANNEL_SSL_STATUS_ERROR:
            return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return count;
}

static int channel_nghttp2_on_frame_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, void *arg) {
    (void) nghttp2;
    struct channel *channel = arg;
    switch (frame->hd.type) {
        case NGHTTP2_GOAWAY:
            logger_debug("Shutting down the connection on channel #%llu by peer request", channel->id);
            channel_on_disconnect(channel, (char const *) frame->goaway.opaque_data, frame->goaway.opaque_data_len);
            break;
    }
    return 0;
}

static int channel_nghttp2_on_header_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, uint8_t const *name, size_t name_len, uint8_t const *value, size_t value_len, uint8_t flags, void *arg) {
    (void) flags;
    (void) arg;
    notification_t *notification = nghttp2_session_get_stream_user_data(nghttp2, frame->hd.stream_id);
    if (!notification) return 0;
    if (name_len == sizeof ":status" - 1 && strncmp((char const *) name, ":status", name_len) == 0) {
        if (value_len != 3) return 0;
        char status_str[4];
        strncpy(status_str, (char const *) value, 3);
        status_str[3] = 0;
        int status = atoi(status_str);
        notification_set_status(notification, status);
        return 0;
    }
    if (name_len == sizeof "apns-id" - 1 && strncmp((char const *) name, "apns-id", name_len) == 0) {
        notification_set_uuid(notification, (char const *) value, value_len);
        return 0;
    }
    return 0;
}

static int channel_nghttp2_on_data_recv(nghttp2_session *nghttp2, uint8_t flags, int32_t stream_id, uint8_t const *buf, size_t len, void *arg) {
    (void) flags;
    (void) arg;
    notification_t *notification = nghttp2_session_get_stream_user_data(nghttp2, stream_id);
    if (!notification) return 0;
    notification_append_response(notification, (char const *) buf, len);
    return 0;
}

static int channel_nghttp2_on_stream_close(nghttp2_session *nghttp2, int32_t stream_id, uint32_t error, void *arg) {
    (void) error;
    notification_t *notification = nghttp2_session_get_stream_user_data(nghttp2, stream_id);
    if (!notification) return 0;
    struct channel *channel = arg;
    channel->handlers.on_respond(notification, channel->arg);
    return 0;
}

static ssize_t channel_nghttp2_do_fetch_data(nghttp2_session *nghttp2, int32_t stream_id, uint8_t *buf, size_t len, uint32_t *flags, nghttp2_data_source *source, void *arg) {
    (void) nghttp2;
    (void) stream_id;
    (void) arg;
    *flags = 0;
    notification_t *notification = source->ptr;
    size_t count = notification_read_payload(notification, (char *) buf, len);
    if (!count) *flags = NGHTTP2_DATA_FLAG_EOF;
    return count;
}

static void channel_cleanup(void) {
    if (channel_evdns_base) evdns_base_free(channel_evdns_base, 1);
    if (channel_event_sigterm) event_free(channel_event_sigterm);
    if (channel_ssl_ctx) SSL_CTX_free(channel_ssl_ctx);
}
