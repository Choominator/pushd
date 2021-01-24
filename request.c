#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>

#include "request.h"
#include "database.h"

#define syslog(l, ...) syslog(l, "[Request] " __VA_ARGS__)

struct request {
    unsigned long long id;
    enum {
        REQUEST_STATE_ROOT,
        REQUEST_STATE_TYPE,
        REQUEST_STATE_EXPIRATION,
        REQUEST_STATE_GROUP,
        REQUEST_STATE_DEVICE,
        REQUEST_STATE_COLLAPSE_ID,
        REQUEST_STATE_PAYLOAD,
        REQUEST_STATE_MEMORY,
        REQUEST_STATE_UNKNOWN
    } state;
    enum {
        REQUEST_TYPE_BACKGROUND,
        REQUEST_TYPE_NORMAL,
        REQUEST_TYPE_URGENT,
        REQUEST_TYPE_REGISTER
    } type;
    unsigned depth;
    yajl_gen generator;
    long long expiration;
    char *group, *device, *collapse_id, *payload;
    size_t group_len, device_len, collapse_id_len, payload_len;
};

static unsigned long long request_count = 0;

static int request_yajl_null(void *data);
static int request_yajl_boolean(void *data, int value);
static int request_yajl_integer(void *data, long long value);
static int request_yajl_double(void *data, double value);
static int request_yajl_string(void *data, unsigned char const *value, size_t len);
static int request_yajl_start_map(void *data);
static int request_yajl_map_key(void *data, unsigned char const *key, size_t len);
static int request_yajl_end_map(void *data);
static int request_yajl_start_array(void *data);
static int request_yajl_end_array(void *data);

static yajl_callbacks request_yajl_callbacks = {
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
    struct request request = {.id = ++ request_count};
    yajl_handle handle = yajl_alloc(&request_yajl_callbacks, NULL, &request);
    if (!handle) {
        syslog(LOG_WARNING, "Not enough memory to parse request %llu", request.id);
        return;
    }
    yajl_status status = yajl_parse(handle, (unsigned char *) json, len);
    if (status == yajl_status_ok) status = yajl_complete_parse(handle);
    if (request.generator) yajl_gen_free(request.generator);
    switch (status) {
        case yajl_status_ok:
            break;
        case yajl_status_client_canceled:
            if (request.state == REQUEST_STATE_MEMORY) syslog(LOG_WARNING, "Not enough memory to parse request %llu", request.id);
            else syslog(LOG_NOTICE, "Request %llu is incorrectly structured", request.id);
            goto parse;
        default:;
            char *error = (char *) yajl_get_error(handle, 0, (unsigned char *) json, len);
            syslog(LOG_NOTICE, "Failed to parse request %llu: %s", request.id, error);
            yajl_free_error(handle, (unsigned char *) error);
            goto parse;
    }
    switch (request.type) {
        case REQUEST_TYPE_BACKGROUND:
            if (request.group && request.collapse_id && request.payload) syslog(LOG_INFO, "Received request %llu to notify group %s in the background with a %zu byte payload", request.id, request.group, request.payload_len);
            else syslog(LOG_NOTICE, "Received request %llu with missing data", request.id);
            break;
        case REQUEST_TYPE_NORMAL:
            if (request.group && request.collapse_id && request.payload) syslog(LOG_INFO, "Received request %llu to notify group %s with a %zu byte payload", request.id, request.group, request.payload_len);
            else syslog(LOG_NOTICE, "Received request %llu with missing data", request.id);
            break;
        case REQUEST_TYPE_URGENT:
            if (request.group && request.collapse_id && request.payload) syslog(LOG_INFO, "Received request %llu to notify group %s urgently with a %zu byte payload", request.id, request.group, request.payload_len);
            else syslog(LOG_NOTICE, "Received request %llu with missing data", request.id);
            break;
        case REQUEST_TYPE_REGISTER:
            if (request.group && request.device) {
                syslog(LOG_INFO, "Received request %llu to register device %s to group %s", request.id, request.device, request.group);
                database_insert_group_device(request.group, request.group_len, request.device, request.device_len);
            } else syslog(LOG_NOTICE, "Received request %llu with missing data", request.id);
            break;
        default:
            abort();
    }
parse:
    yajl_free(handle);
    free(request.group);
    free(request.device);
    free(request.collapse_id);
    free(request.payload);
}

static int request_yajl_null(void *data) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_PAYLOAD:
            if (request->depth <= 1) return 0;
            if (yajl_gen_null(request->generator) != yajl_gen_status_ok) return 0;
        case REQUEST_STATE_UNKNOWN:
            break;
        default:
            return 0;
    }
    return 1;
}

static int request_yajl_boolean(void *data, int value) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_PAYLOAD:
            if (request->depth <= 1) return 0;
            if (yajl_gen_bool(request->generator, value) != yajl_gen_status_ok) return 0;
        case REQUEST_STATE_UNKNOWN:
            break;
        default:
            return 0;
    }
    return 1;
}

static int request_yajl_integer(void *data, long long value) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_EXPIRATION:
            request->expiration = value;
            break;
        case REQUEST_STATE_PAYLOAD:
            if (request->depth <= 1) return 0;
            if (yajl_gen_integer(request->generator, value) != yajl_gen_status_ok) return 0;
        case REQUEST_STATE_UNKNOWN:
            break;
        default:
            return 0;
    }
    return 1;
}

static int request_yajl_double(void *data, double value) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_PAYLOAD:
            if (request->depth <= 1) return 0;
            if (yajl_gen_double(request->generator, value) != yajl_gen_status_ok) return 0;
        case REQUEST_STATE_UNKNOWN:
            break;
        default:
            return 0;
    }
    return 1;
}

static int request_yajl_string(void *data, unsigned char const *value, size_t len) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_TYPE:
            if (len == sizeof "background" - 1 && !strncmp((char *) value, "background", len)) request->type = REQUEST_TYPE_BACKGROUND;
            else if (len == sizeof "normal" - 1 && !strncmp((char *) value, "normal", len)) request->type = REQUEST_TYPE_NORMAL;
            else if (len == sizeof "urgent" - 1 && !strncmp((char *) value, "urgent", len)) request->type = REQUEST_TYPE_URGENT;
            else if (len == sizeof "register" - 1 && !strncmp((char *) value, "register", len)) request->type = REQUEST_TYPE_REGISTER;
            else return 0;
            break;
        case REQUEST_STATE_GROUP:
            free(request->group);
            request->group = strndup((char const *) value, len);
            if (!request->group) goto copy;
            request->group_len = len;
            break;
        case REQUEST_STATE_DEVICE:
            free(request->device);
            request->device = strndup((char const *) value, len);
            if (!request->device) goto copy;
            request->device_len = len;
            break;
        case REQUEST_STATE_COLLAPSE_ID:
            free(request->collapse_id);
            request->collapse_id = strndup((char const *) value, len);
            if (!request->collapse_id) goto copy;
            request->collapse_id_len = len;
            break;
        case REQUEST_STATE_PAYLOAD:
            if (request->depth <= 1) return 0;
            if (yajl_gen_string(request->generator, value, len) != yajl_gen_status_ok) return 0;
        case REQUEST_STATE_UNKNOWN:
            break;
        default: return 0;
    }
    return 1;
copy:
    request->state = REQUEST_STATE_MEMORY;
    return 0;
}

static int request_yajl_start_map(void *data) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_PAYLOAD:
            if (!request->generator) request->generator = yajl_gen_alloc(NULL);
            if (!request->generator) goto generator;
            if (yajl_gen_map_open(request->generator) != yajl_gen_status_ok) return 0;
        case REQUEST_STATE_ROOT:
        case REQUEST_STATE_UNKNOWN:
            ++ request->depth;
            break;
        default:
            return 0;
    }
    return 1;
generator:
    request->state= REQUEST_STATE_MEMORY;
    return 0;
}

static int request_yajl_map_key(void *data, unsigned char const *key, size_t len) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_PAYLOAD:
            if (request->depth > 1) {
                if (yajl_gen_string(request->generator, key, len) != yajl_gen_status_ok) return 0;
                break;
            }
        default:
            if (request->depth > 1) break;
            if (len == sizeof "type" - 1 && !strncmp((char *) key, "type", len)) request->state = REQUEST_STATE_TYPE;
            else if (len == sizeof "expiration" - 1 && !strncmp((char *) key, "expiration", len)) request->state = REQUEST_STATE_EXPIRATION;
            else if (len == sizeof "group" - 1 && !strncmp((char *) key, "group", len)) request->state = REQUEST_STATE_GROUP;
            else if (len == sizeof "device" - 1 && !strncmp((char *) key, "device", len)) request->state = REQUEST_STATE_DEVICE;
            else if (len == sizeof "collapse_id" - 1 && !strncmp((char *) key, "collapse_id", len)) request->state = REQUEST_STATE_COLLAPSE_ID;
            else if (len == sizeof "payload" - 1 && !strncmp((char *) key, "payload", len)) request->state = REQUEST_STATE_PAYLOAD;
            else request->state = REQUEST_STATE_UNKNOWN;
    }
    return 1;
}

static int request_yajl_end_map(void *data) {
    struct request *request = data;
    if (request->depth == 1) return 1;
    -- request->depth;
    switch (request->state) {
        case REQUEST_STATE_PAYLOAD:
            if (yajl_gen_map_close(request->generator) != yajl_gen_status_ok) return 0;
            if (request->depth != 1) break;
            free(request->payload);
            char const *buf;
            size_t len;
            yajl_gen_get_buf(request->generator, (unsigned char const **) &buf, &len);
            request->payload = strndup(buf, len);
            if (!request->payload) goto copy;
            request->payload_len = len;
            yajl_gen_free(request->generator);
            request->generator = NULL;
        case REQUEST_STATE_UNKNOWN:
        case REQUEST_STATE_ROOT:
            break;
        default:
            return 0;
    }
    return 1;
copy:
    request->state = REQUEST_STATE_MEMORY;
    return 0;
}

static int request_yajl_start_array(void *data) {
    struct request *request = data;
    if (!request->depth) return 0;
    ++ request->depth;
    if (request->state == REQUEST_STATE_PAYLOAD) if (yajl_gen_array_open(request->generator) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_end_array(void *data) {
    struct request *request = data;
    if (request->state == REQUEST_STATE_PAYLOAD) if (yajl_gen_array_close(request->generator) != yajl_gen_status_ok) return 0;
    -- request->depth;
    return 1;
}
