#ifndef TRANSPORT
#define TRANSPORT

enum transport_event {
    TRANSPORT_EVENT_CONNECTED,
    TRANSPORT_EVENT_READABLE,
    TRANSPORT_EVENT_WRITABLE,
    TRANSPORT_EVENT_DISCONNECTED,
    TRANSPORT_EVENT_CANCELLED
};

typedef struct transport transport_t;
typedef void (*transport_handler_t)(enum transport_event event, void *arg);
typedef int (*transport_want_t)(void *arg);

void transport_cmdopt(void);
void transport_init(struct event_base *base, char const *host, char const *port);
transport_t *transport_start(transport_handler_t handler, transport_want_t want_read, transport_want_t want_write, void *arg);
int transport_read(transport_t *transport, char *buf, size_t len, size_t *count);
int transport_write(transport_t *transport, char const *buf, size_t len, size_t *count);
void transport_activate(transport_t *transport);
void transport_cancel(transport_t *transport);

#endif
