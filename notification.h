#ifndef NOTIFICATION
#define NOTIFICATION

enum notification_type {
    NOTIFICATION_TYPE_BACKGROUND,
    NOTIFICATION_TYPE_NORMAL,
    NOTIFICATION_TYPE_URGENT
} type;

typedef struct notification notification_t;
typedef struct notification_queue notification_queue_t;

int notification_prepare(void);
void notification_set_type(enum notification_type type);
void notification_set_expiration(time_t expiration);
int notification_add_group(char const *group, size_t len);
int notification_set_key(char const *key, size_t len);
void notification_append_payload(char const *chunk, size_t len);
notification_queue_t *notification_gen_queue(void);
void notification_abort(void);
notification_queue_t *notification_queue_create(void);
void notification_queue_prepend(notification_queue_t *dst, notification_queue_t *src);
void notification_queue_append(notification_queue_t *dst, notification_queue_t *src);
notification_t *notification_queue_peek(notification_queue_t *queue);
void notification_queue_requeue(notification_queue_t *queue, notification_t *notification);
void notification_queue_destroy(notification_queue_t *queue);
unsigned long long notification_get_id(notification_t const *notification);
unsigned long long notification_get_request_id(notification_t const *notification);
enum notification_type notification_get_type(notification_t const *notification);
time_t notification_get_expiration(notification_t const *notification);
void notification_get_device(notification_t const *notification, char const **device, size_t *len);
void notification_get_key(notification_t const *notification, char const **key, size_t *len);
size_t notification_read_payload(notification_t *notification, char *buf, size_t len);
void notification_set_status(notification_t *notification, int status);
void notification_set_uuid(notification_t *notification, char const *uuid, size_t len);
void notification_append_response(notification_t *notification, char const *chunk, size_t len);
int notification_get_status(notification_t *notification);
void notification_get_uuid(notification_t *notification, char const **uuid, size_t *len);
void notification_get_response(notification_t *notification, char const **response, size_t *len);
void notification_destroy(notification_t *notification);

#endif
