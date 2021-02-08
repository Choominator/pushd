#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>

#include <event2/event.h>
#include <nghttp2/nghttp2.h>

#include "notification.h"
#include "transport.h"
#include "cmdopt.h"
#include "dispatch.h"

#define DISPATCH_SERVER_HOST "api.push.apple.com"
#define DISPATCH_SERVER_HOST_SANDBOX "api.sandbox.push.apple.com"
#define DISPATCH_SERVER_PORT "443"
#define DISPATCH_SERVER_PORT_ALT "2197"
#define DISPATCH_REQUEST_RATE "10"
#define DISPATCH_PING_PERIOD "5"
#define DISPATCH_IDLE_TIMEOUT "6"
#define DISPATCH_BUSY_ALARM 60
#define DISPATCH_RESOURCE_BASE_PATH "/3/device/"
#define DISPATCH_DEVICE_LEN 256

#define DISPATCH_NGHTTP2_HEADER(n, v, l, f) {.name = (uint8_t *) (n), .value = (uint8_t *) (v), .namelen = sizeof (n) - 1, .valuelen = (l), .flags = (f) | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE}
#define DISPATCH_NGHTTP2_HEADER_LITERAL(n, v, f) {.name = (uint8_t *) (n), .value = (uint8_t *) (v), .namelen = sizeof n - 1, .valuelen = sizeof v - 1, .flags = (f) | NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE}
#define DISPATCH_NGHTTP2_HEADER_COPY(n, v, l, f) {.name = (uint8_t *) (n), .value = (uint8_t *) (v), .namelen = sizeof (n) - 1, .valuelen = (l), .flags = (f) | NGHTTP2_NV_FLAG_NO_COPY_NAME}

enum dispatch_flags {
    DISPATCH_FLAGS_NONE,
    DISPATCH_FLAGS_SERVER_HOST = 1 << 0,
    DISPATCH_FLAGS_SERVER_PORT = 1 << 1,
    DISPATCH_FLAGS_TERMINATE = 1 << 2
};

struct dispatch_channel {
    unsigned long long id;
    enum {
        DISPATCH_CHANNEL_STATE_DISCONNECTED,
        DISPATCH_CHANNEL_STATE_IDLE,
        DISPATCH_CHANNEL_STATE_BUSY
    } state;
    struct event *event_work, *event_ping, *event_idle;
    notification_queue_t *notification_queue;
    transport_t *transport;
    nghttp2_session *nghttp2;
    struct dispatch_channel *next, *prev;
};

enum dispatch_flags dispatch_flags = DISPATCH_FLAGS_NONE;
static char const *dispatch_request_rate = DISPATCH_REQUEST_RATE;
static char const *dispatch_ping_period = DISPATCH_PING_PERIOD;
static char const *dispatch_idle_timeout = DISPATCH_IDLE_TIMEOUT;
static struct timeval dispatch_timeval_work_period = {.tv_sec = 0, .tv_usec = 0};
static struct timeval dispatch_timeval_ping_period = {.tv_sec = 0, .tv_usec = 0};
static struct timeval dispatch_timeval_idle_timeout = {.tv_sec = 0, .tv_usec = 0};
static struct event_base *dispatch_event_base = NULL;
static struct event *dispatch_event_sigterm = NULL;
static struct event *dispatch_event_busy_alarm = NULL;
static nghttp2_session_callbacks *dispatch_nghttp2_callbacks = NULL;
static notification_queue_t *dispatch_notification_queue = NULL;
static struct dispatch_channel *dispatch_channel_list = NULL;
static unsigned long long dispatch_channel_id = 0;

static void dispatch_channel_start(void);
static void dispatch_channel_halt(struct dispatch_channel *channel);
static void dispatch_event_do_work(evutil_socket_t sd, short events, void *arg);
static void dispatch_event_do_ping(evutil_socket_t sd, short events, void *arg);
static void dispatch_event_on_idle_timeout(evutil_socket_t sd, short events, void *arg);
static void dispatch_event_on_busy_alarm(evutil_socket_t sd, short events, void *arg);
static void dispatch_event_on_signal(evutil_socket_t sd, short events, void *arg);
static void dispatch_transport_on_event(enum transport_event event, void *arg);
static int dispatch_transport_check_want_read(void *arg);
static int dispatch_transport_check_want_write(void *arg);
static ssize_t dispatch_nghttp2_do_recv(nghttp2_session *nghttp2, uint8_t *buf, size_t len, int flags, void *arg);
static ssize_t dispatch_nghttp2_do_send(nghttp2_session *nghttp2, uint8_t const *buf, size_t len, int flags, void *arg);
static int dispatch_nghttp2_on_frame_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, void *arg);
static int dispatch_nghttp2_on_header_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, uint8_t const *name, size_t name_len, uint8_t const *value, size_t value_len, uint8_t flags, void *arg);
static int dispatch_nghttp2_on_data_recv(nghttp2_session *nghttp2, uint8_t flags, int32_t stream_id, uint8_t const *buf, size_t len, void *arg);
static ssize_t dispatch_nghttp2_do_fetch(nghttp2_session *nghttp2, int32_t stream_id, uint8_t *buf, size_t len, uint32_t *flags, nghttp2_data_source *source, void *arg);
static unsigned long dispatch_parse_ulong(char const *value, char const *desc);
static void dispatch_cleanup(void);

void dispatch_cmdopt(void) {
    cmdopt_register('s', "Connect to host " DISPATCH_SERVER_HOST_SANDBOX " instead of " DISPATCH_SERVER_HOST, DISPATCH_FLAGS_SERVER_HOST, (int *) &dispatch_flags, NULL);
    cmdopt_register('p', "Connect to port " DISPATCH_SERVER_PORT_ALT " instead of " DISPATCH_SERVER_PORT, DISPATCH_FLAGS_SERVER_PORT, (int *) &dispatch_flags, NULL);
    cmdopt_register('r', "Limit the rate of requests per second per dispatch channel (0 disables)", 0, NULL, &dispatch_request_rate);
    cmdopt_register('i', "Idle time in minutes before pinging a connection (0 disables)", 0, NULL, &dispatch_ping_period);
    cmdopt_register('t', "Idle time in hours before disconnecting (0 disables)", 0, NULL, &dispatch_idle_timeout);
    transport_cmdopt();
}

void dispatch_init(struct event_base *base) {
    unsigned long value;
    value = dispatch_parse_ulong(dispatch_request_rate, "request rate");
    if (value) dispatch_timeval_work_period = (struct timeval) {.tv_sec = value == 1, .tv_usec = 1000000 / value};
    value = dispatch_parse_ulong(dispatch_ping_period, "ping period");
    dispatch_timeval_ping_period = (struct timeval) {.tv_sec = value * 60};
    value = dispatch_parse_ulong(dispatch_idle_timeout, "idle timeout");
    dispatch_timeval_idle_timeout = (struct timeval) {.tv_sec = value * 60 * 60};
    atexit(dispatch_cleanup);
    dispatch_event_base = base;
    dispatch_event_sigterm = evsignal_new(base, SIGTERM, dispatch_event_on_signal, NULL);
    if (!dispatch_event_sigterm) {
        perror("Unable to register a signal event");
        exit(EXIT_FAILURE);
    }
    if (event_add(dispatch_event_sigterm, NULL) < 0) {
        perror("Unable to add a signal event to the pending set");
        exit(EXIT_FAILURE);
    }
    dispatch_event_busy_alarm = evtimer_new(base, dispatch_event_on_busy_alarm, NULL);
    if (!dispatch_event_busy_alarm) {
        perror("Unable to register a timer event");
        exit(EXIT_FAILURE);
    }
    int status = nghttp2_session_callbacks_new(&dispatch_nghttp2_callbacks);
    if (status) {
        fprintf(stderr, "Unable to initialize the nghttp2 callbacks object: %s\n", nghttp2_strerror(status));
        exit(EXIT_FAILURE);
    }
    nghttp2_session_callbacks_set_recv_callback(dispatch_nghttp2_callbacks, dispatch_nghttp2_do_recv);
    nghttp2_session_callbacks_set_send_callback(dispatch_nghttp2_callbacks, dispatch_nghttp2_do_send);
    nghttp2_session_callbacks_set_on_frame_recv_callback(dispatch_nghttp2_callbacks, dispatch_nghttp2_on_frame_recv);
    nghttp2_session_callbacks_set_on_header_callback(dispatch_nghttp2_callbacks, dispatch_nghttp2_on_header_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(dispatch_nghttp2_callbacks, dispatch_nghttp2_on_data_recv);
    dispatch_notification_queue = notification_queue_create();
    if (!dispatch_notification_queue) {
        perror("Unable to initialize the dispatch notification queue");
        exit(EXIT_FAILURE);
    }
    transport_init(base, ~dispatch_flags & DISPATCH_FLAGS_SERVER_HOST ? DISPATCH_SERVER_HOST : DISPATCH_SERVER_HOST_SANDBOX, ~dispatch_flags & DISPATCH_FLAGS_SERVER_PORT ? DISPATCH_SERVER_PORT : DISPATCH_SERVER_PORT_ALT);
}

void dispatch_enqueue(notification_queue_t *queue) {
    syslog(LOG_INFO, "Appending %llu notifications to the dispatch queue", notification_queue_count(queue));
    notification_queue_append(dispatch_notification_queue, queue);
    if (!dispatch_channel_list) dispatch_channel_start();
    struct dispatch_channel *current;
    for (current = dispatch_channel_list; current && current->state != DISPATCH_CHANNEL_STATE_IDLE; current = current->next);
    if (current) dispatch_event_do_work(-1, 0, current);
}

static void dispatch_channel_start(void) {
    syslog(LOG_INFO, "Starting dispatch channel #%llu", ++ dispatch_channel_id);
    struct dispatch_channel *channel = malloc(sizeof *channel);
    if (!channel) {
        syslog(LOG_WARNING, "Failed to start dispatch channel #%llu due to insufficient memory", dispatch_channel_id);
        goto channel;
    }
    notification_queue_t *notification_queue = notification_queue_create();
    if (!notification_queue) {
        syslog(LOG_WARNING, "Failed to start dispatch channel #%llu due to insufficient memory to create a notification queue", dispatch_channel_id);
        goto queue;
    }
    struct event *event_work = evtimer_new(dispatch_event_base, dispatch_event_do_work, channel);
    if (!event_work) {
        syslog(LOG_WARNING, "Failed to start dispatch channel #%llu due to an error registering a work event: %m", dispatch_channel_id);
        goto event_work;
    }
    struct event *event_ping = NULL;
    if (dispatch_timeval_ping_period.tv_sec) {
        event_ping = evtimer_new(dispatch_event_base, dispatch_event_do_ping, channel);
        if (!event_ping) {
            syslog(LOG_WARNING, "Failed to start dispatch channel #%llu due to an error registering a ping event: %m", dispatch_channel_id);
            goto event_ping;
        }
    }
    struct event *event_idle = NULL;
    if (dispatch_timeval_idle_timeout.tv_sec) {
        event_idle = evtimer_new(dispatch_event_base, dispatch_event_on_idle_timeout, channel);
        if (!event_idle) {
            syslog(LOG_WARNING, "Failed to start dispatch channel #%llu due to an error registering an idle timeout event: %m", dispatch_channel_id);
            goto event_idle;
        }
    }
    transport_t *transport = transport_start(dispatch_transport_on_event, dispatch_transport_check_want_read, dispatch_transport_check_want_write, channel);
    if (!transport) {
        syslog(LOG_NOTICE, "Failed to start dispatch channel #%llu due to a problem with the transport layer", dispatch_channel_id);
        goto transport;
    }
    *channel = (struct dispatch_channel) {.id = dispatch_channel_id, .event_work = event_work, .event_ping = event_ping, .event_idle = event_idle, .state = DISPATCH_CHANNEL_STATE_DISCONNECTED, .notification_queue = notification_queue, .transport = transport, .next = dispatch_channel_list};
    if (dispatch_channel_list) dispatch_channel_list->prev = channel;
    dispatch_channel_list = channel;
    return;
transport:
    if (event_idle) event_free(event_idle);
event_idle:
    if (event_ping) event_free(event_ping);
event_ping:
    event_free(event_work);
event_work:
    notification_queue_destroy(notification_queue);
queue:
    free(channel);
channel:
    if (!dispatch_channel_list) {
        syslog(LOG_ERR, "Terminating due to failing to start dispatch channels");
        exit(EXIT_FAILURE);
    }
}

static void dispatch_channel_halt(struct dispatch_channel *channel) {
    if (channel->transport) {
        transport_cancel(channel->transport);
        return;
    }
    if (channel->nghttp2) {
        syslog(LOG_NOTICE, "Halting dispatch channel #%llu abruptly", channel->id);
        nghttp2_session_del(channel->nghttp2);
    }
    if (channel->event_idle) event_free(channel->event_idle);
    if (channel->event_ping) event_free(channel->event_ping);
    event_free(channel->event_work);
    unsigned long long count = notification_queue_count(channel->notification_queue);
    if (count) {
        syslog(LOG_INFO, "Prepending %llu underlivered notifications from dispatch channel #%llu to the dispatch queue", count, channel->id);
        notification_queue_prepend(dispatch_notification_queue, channel->notification_queue);
    }
    notification_queue_destroy(channel->notification_queue);
    if (channel->next) channel->next->prev = channel->prev;
    if (channel->prev) channel->prev->next = channel->next;
    else dispatch_channel_list = channel->next;
    free(channel);
}

static void dispatch_event_do_work(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    struct dispatch_channel *channel = arg;
    if (dispatch_flags & DISPATCH_FLAGS_TERMINATE) return;
    if (!notification_queue_count(dispatch_notification_queue)) {
        channel->state = DISPATCH_CHANNEL_STATE_IDLE;
        event_del(dispatch_event_busy_alarm);
        if (channel->event_ping && event_add(channel->event_ping, &dispatch_timeval_ping_period) < 0) {
            syslog(LOG_WARNING, "Halting dispatch channel #%llu due to an error scheduling a ping event: %m", channel->id);
            dispatch_channel_halt(channel);
            return;
        }
        if (channel->event_idle && event_add(channel->event_idle, &dispatch_timeval_idle_timeout) < 0) {
            syslog(LOG_WARNING, "Halting dispatch channel #%llu due to an error scheduling an idle timeout event: %m", channel->id);
            dispatch_channel_halt(channel);
            return;
        }
        return;
    }
    notification_t *notification = notification_queue_peek(dispatch_notification_queue);
    char const *device;
    size_t device_len;
    notification_get_device(notification, &device, &device_len);
    char path[sizeof DISPATCH_RESOURCE_BASE_PATH + DISPATCH_DEVICE_LEN];
    size_t path_len = sizeof DISPATCH_RESOURCE_BASE_PATH - 1 + device_len;
    if (path_len >= sizeof path) {
        syslog(LOG_NOTICE, "Dropping notification #%llu because its device token is too long", notification_get_id(notification));
        notification_destroy(notification, dispatch_notification_queue);
        return;
    }
    snprintf(path, sizeof path, DISPATCH_RESOURCE_BASE_PATH "%.*s", (int) device_len, device);
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
    char const *host = ~dispatch_flags & DISPATCH_FLAGS_SERVER_HOST ? DISPATCH_SERVER_HOST : DISPATCH_SERVER_HOST_SANDBOX;
    size_t host_len = ~dispatch_flags & DISPATCH_FLAGS_SERVER_HOST ? sizeof DISPATCH_SERVER_HOST - 1 : sizeof DISPATCH_SERVER_HOST_SANDBOX - 1;
    nghttp2_nv headers[] = {
        DISPATCH_NGHTTP2_HEADER_LITERAL(":method", "POST", NGHTTP2_NV_FLAG_NONE),
        DISPATCH_NGHTTP2_HEADER_LITERAL(":scheme", "https", NGHTTP2_NV_FLAG_NONE),
        DISPATCH_NGHTTP2_HEADER_COPY(":path", path, path_len, NGHTTP2_NV_FLAG_NO_INDEX),
        DISPATCH_NGHTTP2_HEADER("host", host, host_len, NGHTTP2_NV_FLAG_NONE),
        DISPATCH_NGHTTP2_HEADER("apns-push-type", type, type_len, NGHTTP2_NV_FLAG_NONE),
        DISPATCH_NGHTTP2_HEADER_COPY("apns-expiration", expiration, expiration_len, NGHTTP2_NV_FLAG_NO_INDEX),
        DISPATCH_NGHTTP2_HEADER("apns-priority", priority, priority_len, NGHTTP2_NV_FLAG_NONE),
        DISPATCH_NGHTTP2_HEADER("apns-collapse-id", key, key_len, NGHTTP2_NV_FLAG_NO_INDEX)
    };
    nghttp2_data_provider provider = {.source = {.ptr = notification}, .read_callback = dispatch_nghttp2_do_fetch};
    syslog(LOG_INFO, "Dispatching notification #%llu through channel #%llu", notification_get_id(notification), channel->id);
    int32_t stream_id = nghttp2_submit_request(channel->nghttp2, NULL, headers, sizeof headers / sizeof *headers, &provider, notification);
    switch (stream_id) {
        case NGHTTP2_ERR_NOMEM:
            syslog(LOG_WARNING, "Halting dispatch channel #%llu due to insufficient memory", channel->id);
            dispatch_channel_halt(channel);
            return;
        case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
            syslog(LOG_INFO, "Suspending dispatch channel #%llu due to having reached the limit of concurrent streams", channel->id);
            event_del(channel->event_work);
            return;
        default:
            if (stream_id >= 0) {
                transport_activate(channel->transport);
                break;
            }
            syslog(LOG_ERR, "Unexpected error returned by nghttp2: %s", nghttp2_strerror(stream_id));
            abort();
    }
    notification_queue_transfer(channel->notification_queue, dispatch_notification_queue);
    if (channel->state != DISPATCH_CHANNEL_STATE_BUSY) {
        channel->state = DISPATCH_CHANNEL_STATE_BUSY;
        struct dispatch_channel *current;
        for (current = dispatch_channel_list; current && current->state == DISPATCH_CHANNEL_STATE_BUSY; current = current->next);
        if (!current && event_add(dispatch_event_busy_alarm, (struct timeval[]) {{.tv_sec = DISPATCH_BUSY_ALARM}}) < 0) {
            syslog(LOG_ERR, "Failed to schedule a new connection event: %m");
            exit(EXIT_FAILURE);
        }
        if (channel->event_ping) event_del(channel->event_ping);
        if (channel->event_idle) event_del(channel->event_idle);
    }
    if (event_add(channel->event_work, &dispatch_timeval_work_period) < 0) {
        syslog(LOG_WARNING, "Halting dispatch channel #%llu due to an error scheduling the next work event: %m", channel->id);
        dispatch_channel_halt(channel);
    }
}

static void dispatch_event_do_ping(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    struct dispatch_channel *channel = arg;
    if (nghttp2_submit_ping(channel->nghttp2, NGHTTP2_FLAG_NONE, NULL) < 0) {
        syslog(LOG_WARNING, "Halting dispatch channel #%llu due to insufficient memory", channel->id);
        dispatch_channel_halt(channel);
        return;
    }
    if (event_add(channel->event_ping, &dispatch_timeval_ping_period) < 0) {
        syslog(LOG_WARNING, "Halting dispatch channel #%llu due to an error scheduling the next ping event: %m", channel->id);
        dispatch_channel_halt(channel);
    }
    transport_activate(channel->transport);
}

static void dispatch_event_on_idle_timeout(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    struct dispatch_channel *channel = arg;
    syslog(LOG_INFO, "Terminating dispatch channel #%llu due to idle timeout", channel->id);
    if (nghttp2_session_terminate_session(channel->nghttp2, NGHTTP2_NO_ERROR) < 0) {
        syslog(LOG_WARNING, "Halting dispatch channel #%llu due to insufficient memory to terminate its session gracefully", channel->id);
        dispatch_channel_halt(channel);
    }
    transport_activate(channel->transport);
}

static void dispatch_event_on_busy_alarm(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    (void) arg;
    struct dispatch_channel *current;
    for (current = dispatch_channel_list; current && current->state == DISPATCH_CHANNEL_STATE_BUSY; current = current->next);
    if (!current) dispatch_channel_start();
}

static void dispatch_event_on_signal(evutil_socket_t sd, short events, void *arg) {
    (void) events;
    (void) arg;
    switch (sd) {
        case SIGTERM:
            event_del(dispatch_event_sigterm);
            dispatch_flags |= DISPATCH_FLAGS_TERMINATE;
            for (struct dispatch_channel *current = dispatch_channel_list, *next; current; current = next) {
                next = current->next;
                syslog(LOG_INFO, "Terminating dispatch channel #%llu gracefully", current->id);
                if (current->state != DISPATCH_CHANNEL_STATE_DISCONNECTED) {
                    if (nghttp2_session_terminate_session(current->nghttp2, NGHTTP2_NO_ERROR) < 0) {
                        syslog(LOG_WARNING, "Terminating dispatch channel #%llu abruptly due to insufficient memory to perform a graceful shutdown", current->id);
                        dispatch_channel_halt(current);
                        continue;
                    }
                    transport_activate(current->transport);
                } else dispatch_channel_halt(current);
            }
            break;
    }
}

static void dispatch_transport_on_event(enum transport_event event, void *arg) {
    struct dispatch_channel *channel = arg;
    switch (event) {
        case TRANSPORT_EVENT_CONNECTED:
            syslog(LOG_INFO, "Negotiating a session for dispatch channel #%llu with the server", channel->id);
            if (nghttp2_session_client_new(&channel->nghttp2, dispatch_nghttp2_callbacks, channel) < 0 || nghttp2_submit_settings(channel->nghttp2, NGHTTP2_FLAG_NONE, NULL, 0) < 0) {
                syslog(LOG_WARNING, "Halting dispatch channel #%llu due to insufficient memory", channel->id);
                dispatch_channel_halt(channel);
            }
            channel->state = DISPATCH_CHANNEL_STATE_IDLE;
            dispatch_event_do_work(-1, 0, channel);
            break;
        case TRANSPORT_EVENT_READABLE:
            if (nghttp2_session_want_read(channel->nghttp2)) {
                int status = nghttp2_session_recv(channel->nghttp2);
                switch (status) {
                    case 0:
                        break;
                    case NGHTTP2_ERR_EOF:
                        syslog(LOG_NOTICE, "Halting dispatch channel #%llu because the peer closed the connection unexpectedly", channel->id);
                        break;
                    case NGHTTP2_ERR_NOMEM:
                        syslog(LOG_WARNING, "Halting dispatch channel #%llu due to insufficient memory", channel->id);
                        break;
                    case NGHTTP2_ERR_CALLBACK_FAILURE:
                        syslog(LOG_NOTICE, "Halting dispatch channel #%llu due to a connection error", channel->id);
                        break;
                    case NGHTTP2_ERR_FLOODED:
                        syslog(LOG_NOTICE, "Halting dispatch channel #%llu due to flooding by the peer", channel->id);
                        break;
                    default:
                        syslog(LOG_ERR, "Terminating due to an unknown nghttp2 error: %s", nghttp2_strerror(status));
                        abort();
                }
                if (status < 0) {
                    dispatch_channel_halt(channel);
                    break;
                }
            }
            transport_activate(channel->transport);
            break;
        case TRANSPORT_EVENT_WRITABLE:
            if (nghttp2_session_want_write(channel->nghttp2)) {
                int status = nghttp2_session_send(channel->nghttp2);
                switch (status) {
                    case 0:
                        break;
                    case NGHTTP2_ERR_NOMEM:
                        syslog(LOG_WARNING, "Halting dispatch channel #%llu due to insufficient memory", channel->id);
                        break;
                    case NGHTTP2_ERR_CALLBACK_FAILURE:
                        syslog(LOG_NOTICE, "Halting dispatch channel #%llu due to a connection error", channel->id);
                        break;
                    default:
                        syslog(LOG_ERR, "Terminating due to an unexpected nghttp2 error: %s", nghttp2_strerror(status));
                        abort();
                }
                if (status < 0) {
                    dispatch_channel_halt(channel);
                    break;
                }
            }
            transport_activate(channel->transport);
            break;
        case TRANSPORT_EVENT_DISCONNECTED:
            if (nghttp2_session_want_read(channel->nghttp2) || nghttp2_session_want_write(channel->nghttp2)) syslog(LOG_NOTICE, "Halting session from dispatch channel #%llu abruptly due to connection loss", channel->id);
            nghttp2_session_del(channel->nghttp2);
            channel->nghttp2 = NULL;
            channel->state = DISPATCH_CHANNEL_STATE_DISCONNECTED;
            break;
        case TRANSPORT_EVENT_CANCELLED:
            channel->transport = NULL;
            dispatch_channel_halt(channel);
    }
}

static int dispatch_transport_check_want_read(void *arg) {
    struct dispatch_channel *channel = arg;
    return nghttp2_session_want_read(channel->nghttp2);
}

static int dispatch_transport_check_want_write(void *arg) {
    struct dispatch_channel *channel = arg;
    return nghttp2_session_want_write(channel->nghttp2);
}

static ssize_t dispatch_nghttp2_do_recv(nghttp2_session *nghttp2, uint8_t *buf, size_t len, int flags, void *arg) {
    (void) nghttp2;
    (void) flags;
    struct dispatch_channel *channel = arg;
    size_t count;
    int status = transport_read(channel->transport, (char *) buf, len, &count);
    if (status < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (!count) {
        if (status > 0) return NGHTTP2_ERR_EOF;
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    return count;
}

static ssize_t dispatch_nghttp2_do_send(nghttp2_session *nghttp2, uint8_t const *buf, size_t len, int flags, void *arg) {
    (void) nghttp2;
    (void) flags;
    struct dispatch_channel *channel = arg;
    size_t count;
    int status = transport_write(channel->transport, (char const *) buf, len, &count);
    if (status < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (status == 0 && !count) return NGHTTP2_ERR_WOULDBLOCK;
    return count;
}

static int dispatch_nghttp2_on_frame_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, void *arg) {
    (void) nghttp2;
    (void) arg;
    switch (frame->hd.type) {
        case NGHTTP2_GOAWAY:
            syslog(LOG_INFO, "Terminating dispatch channel #%llu  gracefully by peer request");
            break;
    }
    return 0;
}

static int dispatch_nghttp2_on_header_recv(nghttp2_session *nghttp2, nghttp2_frame const *frame, uint8_t const *name, size_t name_len, uint8_t const *value, size_t value_len, uint8_t flags, void *arg) {
    (void) flags;
    struct dispatch_channel *channel = arg;
    notification_t *notification = nghttp2_session_get_stream_user_data(nghttp2, frame->hd.stream_id);
    if (!notification) return 0;
    if (name_len == sizeof ":status" - 1 && strncmp((char const *) name, ":status", name_len) == 0) {
        if (value_len == sizeof "200" - 1 && strncmp((char const *) value, "200", value_len) == 0) syslog(LOG_INFO, "Delivered notification #%llu successfully through dispatch channel #%llu", notification_get_id(notification), channel->id);
        else syslog(LOG_NOTICE, "Delivery of notification #%llu through dispatch channel #%llu failed with status code %.*s", notification_get_id(notification), channel->id, (int) value_len, value);
        notification_destroy(notification, channel->notification_queue);
    }
    return 0;
}

static int dispatch_nghttp2_on_data_recv(nghttp2_session *nghttp2, uint8_t flags, int32_t stream_id, uint8_t const *buf, size_t len, void *arg) {(void) nghttp2; (void) flags; (void) stream_id; (void) buf; (void) len; (void) arg; return 0;}

static ssize_t dispatch_nghttp2_do_fetch(nghttp2_session *nghttp2, int32_t stream_id, uint8_t *buf, size_t len, uint32_t *flags, nghttp2_data_source *source, void *arg) {
    (void) nghttp2;
    (void) stream_id;
    (void) arg;
    *flags = 0;
    notification_t *notification = source->ptr;
    size_t count = notification_read_payload(notification, (char *) buf, len);
    if (!count) *flags = NGHTTP2_DATA_FLAG_EOF;
    return count;
}

static unsigned long dispatch_parse_ulong(char const *value, char const *desc) {
    errno = 0;
    char *end;
    unsigned long ret = strtoul(value, &end, 10);
    if (errno || *end) {
        fprintf(stderr, "Invalid value for %s\n", desc);
        exit(EXIT_FAILURE);
    }
    return ret;
}

static void dispatch_cleanup(void) {
    if (dispatch_notification_queue) notification_queue_destroy(dispatch_notification_queue);
    if (dispatch_nghttp2_callbacks) nghttp2_session_callbacks_del(dispatch_nghttp2_callbacks);
    if (dispatch_event_busy_alarm) event_free(dispatch_event_busy_alarm);
    if (dispatch_event_sigterm) event_free(dispatch_event_sigterm);
}
