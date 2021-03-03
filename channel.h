#ifndef CHANNEL
#define CHANNEL

typedef struct channel channel_t;

enum channel_post_result {
    CHANNEL_POST_RESULT_SUCCESS,
    CHANNEL_POST_RESULT_INVALID,
    CHANNEL_POST_RESULT_BUSY,
    CHANNEL_POST_RESULT_ERROR
};

struct channel_handlers {
    void (*on_connect)(void *arg);
    void (*on_respond)(notification_t *notification, void *arg);
    void (*on_disconnect)(char const *payload, size_t reason_len, void *arg);
    void (*on_cancel)(notification_queue_t *unsent, void *arg);
};

void channel_cmdopt(void);
void channel_init(struct event_base *base);
channel_t *channel_start(struct channel_handlers *handlers, void *arg);
enum channel_post_result channel_post(channel_t *channel, notification_t *notification);
void channel_stop(channel_t *channel);
void channel_cancel(channel_t *channel);

#endif
