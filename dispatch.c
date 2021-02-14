#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>

#include <event2/event.h>

#include "notification.h"
#include "channel.h"
#include "cmdopt.h"
#include "dispatch.h"

#define DISPATCH_REQUEST_RATE "5"
#define DISPATCH_OVERFLOW_ALARM 60

struct dispatch_session {
    unsigned long long id;
    enum {
        DISPATCH_SESSION_STATE_DISCONNECTED,
        DISPATCH_SESSION_STATE_IDLE,
        DISPATCH_SESSION_STATE_BUSY,
        DISPATCH_SESSION_STATE_SUSPENDED
    } state;
    struct event *event_work;
    channel_t *channel;
    struct dispatch_session *next, *prev;
};

static char const *dispatch_request_rate = DISPATCH_REQUEST_RATE;
static struct timeval dispatch_timeval_work_period = {.tv_sec = 0, .tv_usec = 0};
static struct event_base *dispatch_event_base = NULL;
static struct event *dispatch_event_sigterm = NULL;
static struct event *dispatch_event_overflow_alarm = NULL;
static notification_queue_t *dispatch_notification_queue = NULL;
static struct dispatch_session *dispatch_session_list = NULL;
static unsigned long long dispatch_session_id = 0;
static struct timeval dispatch_timeval_last_disconnect = {.tv_sec = 0, .tv_usec = 0};

static void dispatch_assess(void);
static void dispatch_session_start(void);
static void dispatch_session_halt(struct dispatch_session *session);
static void dispatch_event_do_work(evutil_socket_t sd, short events, void *arg);
static void dispatch_event_on_overflow_alarm(evutil_socket_t sd, short events, void *arg);
static void dispatch_event_on_signal(evutil_socket_t sd, short events, void *arg);
static void dispatch_channel_on_connect(void *arg);
static void dispatch_channel_on_respond(notification_t *notification, void *arg);
static void dispatch_channel_on_disconnect(char const *reason, size_t len, void *arg);
static void dispatch_channel_on_cancel(notification_queue_t *unsent, void *arg);
static int dispatch_timeval_subtract(struct timeval *res, struct timeval *left, struct timeval *right);
static void dispatch_cleanup(void);

static struct channel_handlers dispatch_channel_handlers = {
    .on_connect = dispatch_channel_on_connect,
    .on_respond = dispatch_channel_on_respond,
    .on_disconnect = dispatch_channel_on_disconnect,
    .on_cancel = dispatch_channel_on_cancel
};

void dispatch_cmdopt(void) {
    cmdopt_register('r', "Rate of notifications per second per dispatch session (0 disables)", 0, NULL, &dispatch_request_rate);
}

void dispatch_init(struct event_base *base) {
    int value;
    value = atoi(dispatch_request_rate);
    if (value > 0) dispatch_timeval_work_period = (struct timeval) {.tv_sec = value == 1, .tv_usec = 1000000 / value};
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
    dispatch_event_overflow_alarm = evtimer_new(base, dispatch_event_on_overflow_alarm, NULL);
    if (!dispatch_event_overflow_alarm) {
        perror("Unable to register a timer event");
        exit(EXIT_FAILURE);
    }
    dispatch_notification_queue = notification_queue_create();
    if (!dispatch_notification_queue) {
        perror("Unable to initialize the dispatch notification queue");
        exit(EXIT_FAILURE);
    }
}

void dispatch_enqueue(notification_queue_t *queue) {
    notification_queue_append(dispatch_notification_queue, queue);
    dispatch_assess();
}

static void dispatch_assess(void) {
    if (!notification_queue_peek(dispatch_notification_queue)) return;
    if (event_pending(dispatch_event_overflow_alarm, EV_TIMEOUT, NULL)) return;
    if (!dispatch_session_list) {
        struct timeval now;
        event_base_gettimeofday_cached(dispatch_event_base, &now);
        struct timeval then = dispatch_timeval_last_disconnect;
        then.tv_sec += 60;
        struct timeval res;
        if (dispatch_timeval_subtract(&res, &then, &now) < 0) {
            dispatch_session_start();
            return;
        }
        if (event_add(dispatch_event_overflow_alarm, &res) < 0) {
            syslog(LOG_ERR, "Terminating due to an error arming the overflow alarm");
            exit(EXIT_FAILURE);
        }
        return;
    }
    struct dispatch_session *current;
    for (current = dispatch_session_list; current && current->state != DISPATCH_SESSION_STATE_IDLE; current = current->next);
    if (current) dispatch_event_do_work(-1, 0, current);
}

static void dispatch_session_start(void) {
    syslog(LOG_DEBUG, "Starting dispatch session #%llu", ++ dispatch_session_id);
    struct dispatch_session *session = malloc(sizeof *session);
    if (!session) {
        syslog(LOG_WARNING, "Aborting start of dispatch session #%llu due to insufficient memory", dispatch_session_id);
        goto session;
    }
    struct event *event_work = evtimer_new(dispatch_event_base, dispatch_event_do_work, session);
    if (!event_work) {
        syslog(LOG_WARNING, "Aborting start of dispatch session #%llu due to an error creating a work event handler: %m", dispatch_session_id);
        goto event_work;
    }
    channel_t *channel = channel_start(&dispatch_channel_handlers, session);
    if (!channel) {
        syslog(LOG_WARNING, "Aborting start of dispatch session #%llu because its channel failed to start", dispatch_session_id);
        goto channel;
    }
    *session = (struct dispatch_session) {.id = dispatch_session_id, .event_work = event_work, .channel = channel, .next = dispatch_session_list};
    if (dispatch_session_list) dispatch_session_list->prev = session;
    dispatch_session_list = session;
    event_del(dispatch_event_overflow_alarm);
    return;
channel:
    event_free(event_work);
event_work:
    free(session);
session:
    dispatch_assess();
}

static void dispatch_session_halt(struct dispatch_session *session) {
    if (session->channel) {
        channel_cancel(session->channel);
        return;
    }
    syslog(LOG_DEBUG, "Terminating dispatch session #%llu", session->id);
    event_free(session->event_work);
    if (session->next) session->next->prev = session->prev;
    if (session->prev) session->prev->next = session->next;
    else dispatch_session_list = session->next;
    free(session);
}

static void dispatch_event_do_work(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    struct dispatch_session *session = arg;
    if (session->state != DISPATCH_SESSION_STATE_IDLE && session->state != DISPATCH_SESSION_STATE_BUSY) return;
    notification_t *notification = notification_queue_peek(dispatch_notification_queue);
    if (!notification) {
        session->state = DISPATCH_SESSION_STATE_IDLE;
        event_del(dispatch_event_overflow_alarm);
        return;
    }
    int status = channel_post(session->channel, notification);
    switch (status) {
        case 1:
            break;
        case 0:
            session->state = DISPATCH_SESSION_STATE_SUSPENDED;
        case -1:
            return;
    }
    if (session->state < DISPATCH_SESSION_STATE_BUSY) {
        session->state = DISPATCH_SESSION_STATE_BUSY;
        struct dispatch_session *current;
        for (current = dispatch_session_list; current && current->state >= DISPATCH_SESSION_STATE_BUSY; current = current->next);
        if (!current && event_add(dispatch_event_overflow_alarm, (struct timeval[]) {{.tv_sec = DISPATCH_OVERFLOW_ALARM}}) < 0) {
            syslog(LOG_ERR, "Terminating due to an error arming the overflow alarm");
            exit(EXIT_FAILURE);
        }
    }
    if (event_add(session->event_work, &dispatch_timeval_work_period) < 0) {
        syslog(LOG_WARNING, "Aborting dispatch session #%llu due to an error scheduling the next work event: %m", session->id);
        dispatch_session_halt(session);
    }
}

static void dispatch_event_on_overflow_alarm(evutil_socket_t sd, short events, void *arg) {
    (void) sd;
    (void) events;
    (void) arg;
    dispatch_session_start();
}

static void dispatch_event_on_signal(evutil_socket_t sd, short events, void *arg) {
    (void) events;
    (void) arg;
    switch (sd) {
        case SIGTERM:
            event_del(dispatch_event_sigterm);
            for (struct dispatch_session *current = dispatch_session_list, *next; current; current = next) {
                next = current->next;
                channel_stop(current->channel);
            }
            break;
    }
}

static void dispatch_channel_on_connect(void *arg) {
    struct dispatch_session *session = arg;
    session->state = DISPATCH_SESSION_STATE_IDLE;
    dispatch_event_do_work(-1, 0, session);
}

static void dispatch_channel_on_respond(notification_t *notification, void *arg) {
    notification_destroy(notification);
    struct dispatch_session *session = arg;
    if (session->state != DISPATCH_SESSION_STATE_SUSPENDED) return;
    session->state = DISPATCH_SESSION_STATE_BUSY;
    if (event_add(session->event_work, &dispatch_timeval_work_period) < 0) {
        syslog(LOG_WARNING, "Aborting dispatch session #%llu due to an error setting the work event to pending: %m", session->id);
        dispatch_session_halt(session);
    }
}

static void dispatch_channel_on_disconnect(char const *reason, size_t len, void *arg) {
    (void) reason;
    (void) len;
    struct dispatch_session *session = arg;
    syslog(LOG_DEBUG, "Shutting down dispatch session #%llu", session->id);
    session->state = DISPATCH_SESSION_STATE_DISCONNECTED;
}

static void dispatch_channel_on_cancel(notification_queue_t *unsent, void *arg) {
    struct dispatch_session *session = arg;
    session->channel = NULL;
    dispatch_session_halt(session);
    if (unsent) notification_queue_prepend(dispatch_notification_queue, unsent);
    event_base_gettimeofday_cached(dispatch_event_base, &dispatch_timeval_last_disconnect);
    dispatch_assess();
}

static int dispatch_timeval_subtract(struct timeval *res, struct timeval *left, struct timeval *right) {
    if (left->tv_sec < right->tv_sec) return -1;
    if (left->tv_sec == right->tv_sec && left->tv_usec < right->tv_usec) return -1;
    res->tv_sec = left->tv_sec - right->tv_sec;
    res->tv_usec = left->tv_usec + 1000000 - right->tv_usec;
    res->tv_sec += res->tv_usec >= 1000000;
    res->tv_usec %= 1000000;
    return 0;
}

static void dispatch_cleanup(void) {
    if (dispatch_notification_queue) notification_queue_destroy(dispatch_notification_queue);
    if (dispatch_event_overflow_alarm) event_free(dispatch_event_overflow_alarm);
    if (dispatch_event_sigterm) event_free(dispatch_event_sigterm);
}
