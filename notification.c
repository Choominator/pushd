#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/event.h>

#include "logger.h"
#include "database.h"
#include "notification.h"

struct notification {
    unsigned long long id, request_id;
    enum notification_type type;
    time_t expiration;
    char *device, *key, *payload, uuid[36], *response;
    size_t device_len, key_len, payload_len, uuid_len, response_len, payload_consumed;
    int status;
    struct notification *next, *prev, *group_next, *group_prev;
};

struct notification_queue {
    struct notification dummy;
};

static struct notification notification_base;

static void notification_append_string(char **dst, size_t *dst_len, char const *src, size_t src_len);
static size_t notification_next_pow2(size_t value);

int notification_prepare(void) {
    notification_base = (struct notification) {.id = notification_base.id, .request_id = notification_base.request_id + 1};
    if (database_query_reset() < 0) {
        logger_propagate("Preparing notification request #%llu", notification_base.request_id);
        return -1;
    }
    return 0;
}

void notification_set_type(enum notification_type type) {
    notification_base.type = type;
}

void notification_set_expiration(time_t expiration) {
    notification_base.expiration = expiration;
}

int notification_set_key(char const *key, size_t len) {
    free(notification_base.key);
    notification_base.key = strndup(key, len);
    if (!notification_base.key) {
        logger_propagate("Setting the key on notification request #%llu: Allocating memory: %s", notification_base.request_id, strerror(errno));
        return -1;
    }
    notification_base.key_len = len;
    return 0;
}

void notification_append_payload(char const *chunk, size_t len) {
    notification_append_string(&notification_base.payload, &notification_base.payload_len, chunk, len);
}

int notification_add_group(char const *group, size_t len) {
    if (!group) return database_query_reset();
    return database_query_add_group(group, len);
}

notification_queue_t *notification_gen_queue(void) {
    if (!notification_base.payload_len) {
        logger_propagate("Erroneus data");
        goto request;
    }
    struct notification_queue *queue = notification_queue_create();
    if (!queue) goto queue;
    unsigned long long iterations = 0;
    struct notification *last = NULL;
    for (;;) {
        char const *device;
        size_t len;
        int status = database_query_step(&device, &len);
        if (status < 0) goto database;
        if (status == 0) break;
        ++ notification_base.id;
        struct notification *notification = malloc(sizeof *notification);
        if (!notification) {
            logger_propagate("Allocating memory: %s", strerror(errno));
            goto notification;
        }
        *notification = notification_base;
        notification->next = &queue->dummy;
        notification->prev = queue->dummy.prev;
        notification->next->prev = notification;
        notification->prev->next = notification;
        if (last) {
            notification->group_next = last->group_next;
            notification->group_prev = last;
            notification->group_next->group_prev = notification;
            notification->group_prev->group_next = notification;
            last = notification;
        } else notification->group_next = notification->group_prev = last = notification;
        notification->device = strndup(device, len);
        notification->device_len = len;
        if (!notification->device) {
            logger_propagate("Generating notification #%llu: Copying the device token: %s", notification_base.id, strerror(errno));
            notification_destroy(notification);
            goto device;
            break;
        }
        ++ iterations;
    }
    logger_debug("Generated %llu notifications from request #%llu", iterations, notification_base.request_id);
    if (iterations) return queue;
    else logger_propagate("No notifications generated");
device:
notification:
    database_query_abort();
database:
    notification_queue_destroy(queue);
queue:
request:
    free(notification_base.key);
    free(notification_base.payload);
    logger_propagate("Generating notifications from request #%llu", notification_base.request_id);
    return NULL;
}

void notification_abort(void) {
    database_query_abort();
}

notification_queue_t *notification_queue_create(void) {
    struct notification_queue *queue = malloc(sizeof *queue);
    if (!queue) {
        logger_propagate("Creating a notification queue: Allocating memory: %s", strerror(errno));
        return NULL;
    }
    *queue = (struct notification_queue) {.dummy = {.next = &queue->dummy, .prev = &queue->dummy}};
    return queue;
}

void notification_queue_prepend(notification_queue_t *dst, notification_queue_t *src) {
    if (src->dummy.next == &src->dummy) return;
    src->dummy.next->prev = &dst->dummy;
    src->dummy.prev->next = dst->dummy.next;
    dst->dummy.next->prev = src->dummy.prev;
    dst->dummy.next = src->dummy.next;
    *src = (struct notification_queue) {.dummy = {.next = &src->dummy, .prev = &src->dummy}};
}

void notification_queue_append(notification_queue_t *dst, notification_queue_t *src) {
    if (src->dummy.next == &src->dummy) return;
    src->dummy.next->prev = dst->dummy.prev;
    src->dummy.prev->next = &dst->dummy;
    dst->dummy.prev->next = src->dummy.next;
    dst->dummy.prev = src->dummy.prev;
    *src = (struct notification_queue) {.dummy = {.next = &src->dummy, .prev = &src->dummy}};
}

notification_t *notification_queue_peek(notification_queue_t *queue) {
    if (queue->dummy.next == &queue->dummy) return NULL;
    return queue->dummy.next;
}

void notification_queue_requeue(notification_queue_t *queue, notification_t *notification) {
    notification->next->prev = notification->prev;
    notification->prev->next = notification->next;
    notification->next = queue->dummy.next;
    notification->prev = &queue->dummy;
    notification->next->prev = notification;
    notification->prev->next = notification;
}

void notification_queue_destroy(notification_queue_t *queue) {
    while (queue->dummy.next != &queue->dummy) notification_destroy(queue->dummy.next);
    free(queue);
}

unsigned long long notification_get_id(notification_t const *notification) {
    if (!notification) return notification_base.id;
    return notification->id;
}

enum notification_type notification_get_type(notification_t const *notification) {
    return notification->type;
}

time_t notification_get_expiration(notification_t const *notification) {
    return notification->expiration;
}

void notification_get_device(notification_t const *notification, char const **device, size_t *len) {
    *device = notification->device;
    *len = notification->device_len;
}

void notification_get_key(notification_t const *notification, char const **key, size_t *len) {
    *key = notification->key;
    *len = notification->key_len;
}

size_t notification_read_payload(notification_t *notification, char *buf, size_t len) {
    size_t count = notification->payload_len - notification->payload_consumed;
    if (count > len) count = len;
    memcpy(buf, notification->payload + notification->payload_consumed, count);
    notification->payload_consumed += count;
    return count;
}

void notification_set_status(notification_t *notification, int status) {
    notification->status = status;
}

void notification_set_uuid(notification_t *notification, char const *uuid, size_t len) {
    if (len > sizeof notification->uuid) len = sizeof notification->uuid;
    strncpy(notification->uuid, uuid, len);
    notification->uuid_len = len;
}

void notification_append_response(notification_t *notification, char const *chunk, size_t len) {
    notification_append_string(&notification->response, &notification->response_len, chunk, len);
}

int notification_get_status(notification_t *notification) {
    return notification->status;
}

void notification_get_uuid(notification_t *notification, char const **uuid, size_t *len) {
    *uuid = notification->uuid_len ? notification->uuid : NULL;
    *len = notification->uuid_len;
}

void notification_get_response(notification_t *notification, char const **response, size_t *len) {
    *response = notification->response;
    *len = notification->response ? notification->response_len : 0;
}

void notification_destroy(notification_t *notification) {
    notification->next->prev = notification->prev;
    notification->prev->next = notification->next;
    free(notification->device);
    free(notification->response);
    if (notification->group_next != notification) {
        notification->group_next->group_prev = notification->group_prev;
        notification->group_prev->group_next = notification->group_next;
    } else {
        free(notification->key);
        free(notification->payload);
        logger_debug("Freed resources from request #%llu", notification->request_id);
    }
    unsigned long long id = notification->id;
    free(notification);
    logger_debug("Destroyed notification #%llu", id);
}

static void notification_append_string(char **dst, size_t *dst_len, char const *src, size_t src_len) {
    if (!src) {
        free(*dst);
        *dst = NULL;
        *dst_len = 0;
    }
    if (!*dst && *dst_len) return;
    *dst_len += src_len;
    char *tmp = realloc(*dst, notification_next_pow2(*dst_len));
    if (!tmp) {
        free(*dst);
        *dst = NULL;
        return;
    }
    *dst = tmp;
    memcpy(tmp + *dst_len - src_len, src, src_len);
}

static size_t notification_next_pow2(size_t value) {
    -- value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    value |= value >> 32;
    ++ value;
    return value;
}
