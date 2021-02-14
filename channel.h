#ifndef CHANNEL
#define CHANNEL

typedef struct channel channel_t;

struct channel_handlers {
    void (*on_connect)(void *arg);
    void (*on_respond)(notification_t *notification, void *arg);
    void (*on_disconnect)(char const *reason, size_t reason_len, void *arg);
    void (*on_cancel)(notification_queue_t *unsent, void *arg);
};

void channel_cmdopt(void);
void channel_init(struct event_base *base);
channel_t *channel_start(struct channel_handlers *handlers, void *arg);
int channel_post(channel_t *channel, notification_t *notification);
void channel_stop(channel_t *channel);
void channel_cancel(channel_t *channel);

#endif
