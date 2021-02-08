#ifndef NOTIFICATION
#define NOTIFICATION

enum notification_type {
    NOTIFICATION_TYPE_BACKGROUND,
    NOTIFICATION_TYPE_NORMAL,
    NOTIFICATION_TYPE_URGENT
} type;

typedef struct notification notification_t;
typedef struct notification_request notification_request_t;
typedef struct notification_queue notification_queue_t;

notification_request_t *notification_request_create(unsigned long long id);
void notification_request_set_type(notification_request_t *request, enum notification_type type);
void notification_request_set_expiration(notification_request_t *request, time_t expiration);
int notification_request_set_group(notification_request_t *request, char const *group, size_t len);
int notification_request_set_key(notification_request_t *request, char const *key, size_t len);
int notification_request_set_payload(notification_request_t *request, char const *payload, size_t len);
void notification_request_destroy(notification_request_t *request);
notification_queue_t *notification_request_make_queue(notification_request_t *request);
notification_queue_t *notification_queue_create(void);
void notification_queue_prepend(notification_queue_t *dst, notification_queue_t *src);
void notification_queue_append(notification_queue_t *dst, notification_queue_t *src);
void notification_queue_transfer(notification_queue_t *dst, notification_queue_t *src);
notification_t *notification_queue_peek(notification_queue_t *queue);
unsigned long long notification_queue_count(notification_queue_t const *queue);
void notification_queue_destroy(notification_queue_t *queue);
unsigned long long notification_get_id(notification_t const *notification);
unsigned long long notification_get_request_id(notification_t const *notification);
enum notification_type notification_get_type(notification_t const *notification);
time_t notification_get_expiration(notification_t const *notification);
void notification_get_device(notification_t const *notification, char const **device, size_t *len);
void notification_get_key(notification_t const *notification, char const **key, size_t *len);
size_t notification_read_payload(notification_t *notification, char *buf, size_t len);
void notification_destroy(notification_t *notification, notification_queue_t *queue);

#endif
