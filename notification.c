#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>

#include "notification.h"
#include "database.h"

struct notification_request;

struct notification {
    unsigned long long id;
    char *device, *uuid, *response;
    size_t device_len, uuid_len, response_len, payload_consumed;
    int status;
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
    struct notification dummy;
};

static unsigned long long notification_id = 0;

notification_request_t *notification_request_create(unsigned long long id) {
    syslog(LOG_DEBUG, "Creating request #%llu", id);
    struct notification_request *request = malloc(sizeof *request);
    if (!request) {
        syslog(LOG_WARNING, "Aborting the creation of request #%llu due to insufficient memory", id);
        return NULL;
    }
    *request = (struct notification_request) {.id = id, .refcount = 1};
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

void notification_request_release(notification_request_t *request) {
    -- request->refcount;
    if (request->refcount) return;
    syslog(LOG_DEBUG, "Destroying request #%llu", request->id);
    free(request->group);
    free(request->key);
    free(request->payload);
    free(request);
}

notification_queue_t *notification_request_make_queue(notification_request_t *request) {
    syslog(LOG_DEBUG, "Generating a notification queue from request #%llu", request->id);
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
        syslog(LOG_NOTICE, "Dropping request #%llu due to missing fields:%s%s%s", request->id, missing & MISSING_GROUP ? " group" : "", missing & MISSING_KEY ? " key" : "", missing & MISSING_PAYLOAD ? " payload" : "");
        return NULL;
    }
    struct notification_queue *queue = notification_queue_create();
    if (!queue) {
        syslog(LOG_WARNING, "Dropping request #%llu due to insufficient memory to create the queue", request->id);
        return NULL;
    }
    if (database_select_group_devices(request->group, request->group_len) < 0) {
        syslog(LOG_WARNING, "Dropping request #%llu due to an error querying the database", request->id);
        notification_queue_destroy(queue);
        return NULL;
    }
    size_t iterations = 0;
    for (;;) {
        char const *device;
        size_t len;
        int status = database_next_device(&device, &len);
        if (status < 1) break;
        syslog(LOG_DEBUG, "Creating notification #%llu for request #%llu", ++ notification_id, request->id);
        struct notification *notification = malloc(sizeof *notification);
        if (!notification) {
            syslog(LOG_WARNING, "Aborting the creation of notification #%llu due to insufficient memory", notification_id);
            break;
        }
        *notification = (struct notification) {.id = notification_id, .device = strndup(device, len), .device_len = len, .request = request, .next = &queue->dummy, .prev = queue->dummy.prev};
        notification->next->prev = notification;
        notification->prev->next = notification;
        ++ request->refcount;
        if (!notification->device) {
            syslog(LOG_WARNING, "Dropping notification #%llu due to insufficient memory to copy the device token", notification_id);
            notification_destroy(notification);
            break;
        }
        ++ iterations;
    }
    if (iterations) return queue;
    notification_queue_destroy(queue);
    return NULL;
}

notification_queue_t *notification_queue_create(void) {
    struct notification_queue *queue = malloc(sizeof *queue);
    if (!queue) return NULL;
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

void notification_queue_transfer_notification(notification_queue_t *queue, notification_t *notification) {
    notification->next->prev = notification->prev;
    notification->prev->next = notification->next;
    notification->next = &queue->dummy;
    notification->prev = queue->dummy.prev;
    notification->next->prev = notification;
    notification->prev->next = notification;
}

void notification_queue_destroy(notification_queue_t *queue) {
    while (queue->dummy.next != &queue->dummy) notification_destroy(queue->dummy.next);
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

void notification_set_status(notification_t *notification, int status) {
    notification->status = status;
}

void notification_set_uuid(notification_t *notification, char const *uuid, size_t len) {
    free(notification->uuid);
    notification->uuid = strndup(uuid, len);
    if (!notification->uuid) {
        syslog(LOG_WARNING, "Ignoring the UUID for notification #%llu due to insufficient memory", notification->id);
        return;
    }
    notification->uuid_len = len;
}

void notification_append_response(notification_t *notification, char const *response, size_t len) {
    if (!notification->response && notification->response_len) return;
    notification->response_len += len;
    char *tmp = realloc(notification->response, notification->response_len);
    if (!tmp) {
        syslog(LOG_WARNING, "Ignoring the response for notification #%llu due to insufficient memory", notification->id);
        free(notification->response);
        notification->response = NULL;
        return;
    }
    notification->response = tmp;
    memcpy(tmp + notification->response_len - len, response, len);
}

int notification_get_status(notification_t *notification) {
    return notification->status;
}

void notification_get_uuid(notification_t *notification, char const **uuid, size_t *len) {
    *uuid = notification->uuid;
    *len = notification->uuid_len;
}

void notification_get_response(notification_t *notification, char const **response, size_t *len) {
    *response = notification->response;
    *len = notification->response ? notification->response_len : 0;
}

void notification_destroy(notification_t *notification) {
    syslog(LOG_DEBUG, "Destroying notification #%llu", notification->id);
    notification_request_release(notification->request);
    notification->next->prev = notification->prev;
    notification->prev->next = notification->next;
    free(notification->device);
    free(notification->response);
    free(notification->uuid);
    free(notification);
}
