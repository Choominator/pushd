#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>
#include <event2/event.h>

#include "notification.h"
#include "dispatch.h"
#include "request.h"

struct request {
    enum {
        REQUEST_STATE_NONE,
        REQUEST_STATE_MEMORY,
        REQUEST_STATE_ROOT,
        REQUEST_STATE_TYPE,
        REQUEST_STATE_EXPIRATION,
        REQUEST_STATE_GROUP,
        REQUEST_STATE_KEY,
        REQUEST_STATE_PAYLOAD
    } state;
    notification_request_t *notification_request;
    yajl_gen generator;
};

static int request_yajl_null(void *arg);
static int request_yajl_boolean(void *arg, int value);
static int request_yajl_integer(void *arg, long long value);
static int request_yajl_double(void *arg, double value);
static int request_yajl_string(void *arg, unsigned char const *value, size_t len);
static int request_yajl_start_map(void *arg);
static int request_yajl_map_key(void *arg, unsigned char const *key, size_t len);
static int request_yajl_end_map(void *arg);
static int request_yajl_start_array(void *arg);
static int request_yajl_end_array(void *arg);
static void request_yajl_append(void *arg, char const *chunk, size_t len);

static yajl_callbacks const request_yajl_callbacks = {
    .yajl_null = request_yajl_null,
    .yajl_boolean = request_yajl_boolean,
    .yajl_integer = request_yajl_integer,
    .yajl_double = request_yajl_double,
    .yajl_string = request_yajl_string,
    .yajl_start_map = request_yajl_start_map,
    .yajl_map_key = request_yajl_map_key,
    .yajl_end_map = request_yajl_end_map,
    .yajl_start_array = request_yajl_start_array,
    .yajl_end_array = request_yajl_end_array
};

void request_process(char const *json, size_t len) {
    struct request request = {.state = REQUEST_STATE_NONE};
    request.notification_request = notification_request_create();
    if (!request.notification_request) {
        syslog(LOG_WARNING, "Dropping notification request due to insufficient memory to process it");
        return;
    }
    yajl_handle yajl = yajl_alloc(&request_yajl_callbacks, NULL, &request);
    if (!yajl) {
        syslog(LOG_WARNING, "Dropping notification request #%llu due to insufficient memory to parse it", notification_request_get_id(request.notification_request));
        goto yajl;
    }
    yajl_status status = yajl_parse(yajl, (unsigned char *) json, len);
    if (status == yajl_status_ok) status = yajl_complete_parse(yajl);
    if (request.generator) yajl_gen_free(request.generator);
    if (status != yajl_status_ok) {
        if (request.state != REQUEST_STATE_MEMORY) syslog(LOG_NOTICE, "Dropping notification request #%llu due to a parse error", notification_request_get_id(request.notification_request));
        else syslog(LOG_WARNING, "Dropping notification request #%llu due to insufficient memory to parse it", notification_request_get_id(request.notification_request));
        goto parse;
    }
    notification_queue_t *queue = notification_request_make_queue(request.notification_request);
    if (queue) dispatch_enqueue(queue);
parse:
    yajl_free(yajl);
yajl:
    notification_request_release(request.notification_request);
}

static int request_yajl_null(void *arg) {
    struct request *request = arg;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    if (yajl_gen_null(request->generator) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_boolean(void *arg, int value) {
    struct request *request = arg;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    if (yajl_gen_bool(request->generator, value) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_integer(void *arg, long long value) {
    struct request *request = arg;
    switch (request->state) {
        case REQUEST_STATE_EXPIRATION:
            notification_request_set_expiration(request->notification_request, value);
            break;
        default:
            if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
            if (yajl_gen_integer(request->generator, value) != yajl_gen_status_ok) return 0;
    }
    if (request->state < REQUEST_STATE_PAYLOAD) request->state = REQUEST_STATE_ROOT;
    return 1;
}

static int request_yajl_double(void *arg, double value) {
    struct request *request = arg;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    if (yajl_gen_double(request->generator, value) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_string(void *arg, unsigned char const *value, size_t len) {
    struct request *request = arg;
    switch (request->state) {
        case REQUEST_STATE_TYPE:
            if (len == sizeof "background" - 1 && strncmp((char const *) value, "background", len) == 0) notification_request_set_type(request->notification_request, NOTIFICATION_TYPE_BACKGROUND);
            else if (len == sizeof "normal" - 1 && strncmp((char const *) value, "normal", len) == 0) notification_request_set_type(request->notification_request, NOTIFICATION_TYPE_NORMAL);
            else if (len == sizeof "urgent" - 1 && strncmp((char const *) value, "urgent", len) == 0) notification_request_set_type(request->notification_request, NOTIFICATION_TYPE_URGENT);
            else return 0;
        case REQUEST_STATE_GROUP:
            if (notification_request_set_group(request->notification_request, (char const *) value, len) < 0) goto copy;
            break;
        case REQUEST_STATE_KEY:
            if (notification_request_set_key(request->notification_request, (char const *) value, len) < 0) goto copy;
            break;
        default:
            if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
            if (yajl_gen_string(request->generator, value, len) != yajl_gen_status_ok) return 0;
    }
    if (request->state < REQUEST_STATE_PAYLOAD) request->state = REQUEST_STATE_ROOT;
    return 1;
copy:
    request->state = REQUEST_STATE_MEMORY;
    return 0;
}

static int request_yajl_start_map(void *arg) {
    struct request *request = arg;
    if (request->state == REQUEST_STATE_NONE) {
        request->state = REQUEST_STATE_ROOT;
        return 1;
    }
    if (request->state < REQUEST_STATE_PAYLOAD) return 0;
    if (request->state == REQUEST_STATE_PAYLOAD) {
        notification_request_append_payload(request->notification_request, NULL, 0);
        request->generator = yajl_gen_alloc(NULL);
        if (!request->generator) {
            request->state= REQUEST_STATE_MEMORY;
            return 0;
        }
        yajl_gen_config(request->generator, yajl_gen_print_callback, request_yajl_append);
    }
    if (yajl_gen_map_open(request->generator) != yajl_gen_status_ok) return 0;
    ++ request->state;
    return 1;
}

static int request_yajl_map_key(void *arg, unsigned char const *key, size_t len) {
    struct request *request = arg;
    if (request->state > REQUEST_STATE_PAYLOAD) {
        if (yajl_gen_string(request->generator, key, len) != yajl_gen_status_ok) return 0;
        return 1;
    }
    if (len == sizeof "type" - 1 && strncmp((char const *) key, "type", len) == 0) request->state = REQUEST_STATE_TYPE;
    else if (len == sizeof "expiration" - 1 && strncmp((char const *) key, "expiration", len) == 0) request->state = REQUEST_STATE_EXPIRATION;
    else if (len == sizeof "group" - 1 && strncmp((char const *) key, "group", len) == 0) request->state = REQUEST_STATE_GROUP;
    else if (len == sizeof "key" - 1 && strncmp((char const *) key, "key", len) == 0) request->state = REQUEST_STATE_KEY;
    else if (len == sizeof "payload" - 1 && strncmp((char const *) key, "payload", len) == 0) request->state = REQUEST_STATE_PAYLOAD;
    else return 0;
    return 1;
}

static int request_yajl_end_map(void *arg) {
    struct request *request = arg;
    if (request->state == REQUEST_STATE_ROOT) return 1;
    -- request->state;
    if (yajl_gen_map_close(request->generator) != yajl_gen_status_ok) return 0;
    if (request->state != REQUEST_STATE_PAYLOAD) return 1;
    yajl_gen_free(request->generator);
    request->generator = NULL;
    request->state = REQUEST_STATE_ROOT;
    return 1;
}

static int request_yajl_start_array(void *arg) {
    struct request *request = arg;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    ++ request->state;
    if (yajl_gen_array_open(request->generator) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_end_array(void *arg) {
    struct request *request = arg;
    if (yajl_gen_array_close(request->generator) != yajl_gen_status_ok) return 0;
    -- request->state;
    return 1;
}

static void request_yajl_append(void *arg, char const *chunk, size_t len) {
    struct request *request = arg;
    notification_request_append_payload(request->notification_request, chunk, len);
}
