#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include "notification.h"
#include "database.h"

struct notification_request;

struct notification {
    unsigned long long id;
    char *device;
    size_t device_len, payload_consumed;
    struct notification_request *request;
    struct notification *next, *prev;
};

struct notification_request {
    unsigned long long id;
    enum notification_type type;
    time_t expiration;
    char *group, *key, *payload;
    size_t group_len, key_len, payload_len, refcount;
};

struct notification_queue {
    struct notification *head, *tail;
    size_t count;
};

static unsigned long long notification_id = 0;

notification_request_t *notification_request_create(unsigned long long id) {
    struct notification_request *request = malloc(sizeof *request);
    if (!request) return NULL;
    *request = (struct notification_request) {.id = id};
    return request;
}

void notification_request_set_type(notification_request_t *request, enum notification_type type) {
    request->type = type;
}

void notification_request_set_expiration(notification_request_t *request, time_t expiration) {
    request->expiration = expiration;
}

int notification_request_set_group(notification_request_t *request, char const *group, size_t len) {
    free(request->group);
    request->group = strndup(group, len);
    if (!request->group) return -1;
    request->group_len = len;
    return 0;
}

int notification_request_set_key(notification_request_t *request, char const *key, size_t len) {
    free(request->key);
    request->key = strndup(key, len);
    if (!request->key) return -1;
    request->key_len = len;
    return 0;
}

int notification_request_set_payload(notification_request_t *request, char const *payload, size_t len) {
    free(request->payload);
    request->payload = strndup(payload, len);
    if (!request->payload) return -1;
    request->payload_len = len;
    return 0;
}

void notification_request_destroy(notification_request_t *request) {
    if (request->refcount) {
        syslog(LOG_ERR, "Attempting to destroy a notification request with a non-zero reference count");
        abort();
    }
    free(request->group);
    free(request->key);
    free(request->payload);
    free(request);
}

notification_queue_t *notification_request_make_queue(notification_request_t *request) {
    enum {
        MISSING_NONE,
        MISSING_GROUP = 1 << 0,
        MISSING_KEY = 1 << 1,
        MISSING_PAYLOAD = 1 << 2
    } missing = MISSING_NONE;
    if (!request->group || !*request->group) missing |= MISSING_GROUP;
    if (!request->key || !*request->key) missing |= MISSING_KEY;
    if (!request->payload || !*request->payload) missing |= MISSING_PAYLOAD;
    if (missing) {
        syslog(LOG_NOTICE, "Dropping notification request #%llu due to missing fields:%s%s%s", request->id, missing & MISSING_GROUP ? " group" : "", missing & MISSING_KEY ? " key" : "", missing & MISSING_PAYLOAD ? " payload" : "");
        return NULL;
    }
    struct notification_queue *queue = notification_queue_create();
    if (!queue) {
        syslog(LOG_WARNING, "Dropping notification request #%llu due to insufficient memory", request->id);
        return NULL;
    }
    if (database_select_group_devices(request->group, request->group_len) < 0) {
        syslog(LOG_WARNING, "Dropping notification request #%llu due to a database error", request->id);
        goto query;
    }
    for (;;) {
        char const *device;
        size_t len;
        int status = database_next_device(&device, &len);
        if (status < 0) {
            syslog(LOG_WARNING, "Droping notification request #%llu due to an error querying the database", request->id);
            goto query;
        } else if (!status) break;
        struct notification *notification = malloc(sizeof *notification);
        if (!notification) goto notification;
        *notification = (struct notification) {.id = ++ notification_id, .device = strndup(device, len), .device_len = len, .request = request, .prev = queue->tail};
        ++ request->refcount;
        if (queue->tail) queue->tail->next = notification;
        else queue->head = notification;
        queue->tail = notification;
        ++ queue->count;
        if (!device) {
            syslog(LOG_WARNING, "Dropping notification request #%llu due to insufficient memory", request->id);
            goto notification;
        }
    }
    return queue;
notification:
query:
    notification_queue_destroy(queue);
    return NULL;
}

notification_queue_t *notification_queue_create(void) {
    struct notification_queue *queue = malloc(sizeof *queue);
    if (!queue) return NULL;
    *queue = (struct notification_queue) {.count = 0};
    return queue;
}

void notification_queue_prepend(notification_queue_t *dst, notification_queue_t *src) {
    if (!src->count) return;
    src->tail->next = dst->head;
    if (dst->head) dst->head->prev = src->tail;
    else dst->tail = src->tail;
    dst->head = src->head;
    dst->count += src->count;
    *src = (struct notification_queue) {.count = 0};
}

void notification_queue_append(notification_queue_t *dst, notification_queue_t *src) {
    if (!src->count) return;
    src->head->prev = dst->tail;
    if (dst->tail) dst->tail->next = src->head;
    else dst->head = src->head;
    dst->tail = src->tail;
    dst->count += src->count;
    *src = (struct notification_queue) {.count = 0};
}

void notification_queue_transfer(notification_queue_t *dst, notification_queue_t *src) {
    if (!src->count) return;
    struct notification *current = src->head;
    src->head = current->next;
    if (src->head) src->head->prev = NULL;
    else src->tail = NULL;
    -- src->count;
    current->prev = dst->tail;
    if (dst->tail) dst->tail->next = current;
    else dst->head = current;
    dst->tail = current;
    ++ dst->count;
    current->next = NULL;
}

notification_t *notification_queue_peek(notification_queue_t *queue) {
    return queue->head;
}

unsigned long long notification_queue_count(notification_queue_t const *queue) {
    return queue->count;
}

void notification_queue_destroy(notification_queue_t *queue) {
    while (queue->head) {
        struct notification *current = queue->head;
        queue->head = current->next;
        free(current->device);
        -- current->request->refcount;
        if (!current->request->refcount) notification_request_destroy(current->request);
        free(current);
    }
    free(queue);
}

unsigned long long notification_get_id(notification_t const *notification) {
    return notification->id;
}

unsigned long long notification_get_request_id(notification_t const *notification) {
    return notification->request->id;
}

enum notification_type notification_get_type(notification_t const *notification) {
    return notification->request->type;
}

time_t notification_get_expiration(notification_t const *notification) {
    return notification->request->expiration;
}

void notification_get_device(notification_t const *notification, char const **device, size_t *len) {
    *device = notification->device;
    *len = notification->device_len;
}

void notification_get_key(notification_t const *notification, char const **key, size_t *len) {
    *key = notification->request->key;
    *len = notification->request->key_len;
}

size_t notification_read_payload(notification_t *notification, char *buf, size_t len) {
    size_t count = notification->request->payload_len - notification->payload_consumed;
    if (count > len) count = len;
    memcpy(buf, notification->request->payload + notification->payload_consumed, count);
    notification->payload_consumed += count;
    return count;
}

void notification_destroy(notification_t *notification, notification_queue_t *queue) {
    if (notification->next) notification->next->prev = notification->prev;
    else queue->tail = notification->prev;
    if (notification->prev) notification->prev->next = notification->next;
    else queue->head = notification->next;
    -- queue->count;
    free(notification->device);
    -- notification->request->refcount;
    if (!notification->request->refcount) notification_request_destroy(notification->request);
    free(notification);
}
