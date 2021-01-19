#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <yajl/yajl_parse.h>

#define syslog(l, ...) syslog(l, "[Request] " __VA_ARGS__)

struct request {
    unsigned long long id;
    enum {
        REQUEST_STATE_NONE,
        REQUEST_STATE_MEMORY,
        REQUEST_STATE_TYPE,
        REQUEST_STATE_EXPIRATION,
        REQUEST_STATE_USER,
        REQUEST_STATE_COLLAPSE_ID,
        REQUEST_STATE_PAYLOAD
    } state;
    enum {
        REQUEST_TYPE_BACKGROUND,
        REQUEST_TYPE_NORMAL,
        REQUEST_TYPE_URGENT
    } type;
    long long expiration;
    char *user;
    char *collapse_id;
    char *payload;
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
    struct request request = {.id = request_count ++};
    yajl_handle handle = yajl_alloc(&request_yajl_callbacks, NULL, &request);
    if (!handle) {
        syslog(LOG_WARNING, "Not enough memory to parse request %llu", request.id);
        return;
    }
    yajl_status status = yajl_parse(handle, (unsigned char *) json, len);
    if (status == yajl_status_ok) status = yajl_complete_parse(handle);
    switch (status) {
        case yajl_status_ok:
            break;
        case yajl_status_client_canceled:
            if (request.state == REQUEST_STATE_MEMORY) syslog(LOG_WARNING, "Not enough memory to parse request %llu", request.id);
            else syslog(LOG_WARNING, "Request %llu contains invalid data", request.id);
            goto parse;
        default:;
            char *error = (char *) yajl_get_error(handle, 0, (unsigned char *) json, len);
            syslog(LOG_WARNING, "Failed to parse request %llu: %s", request.id, error);
            yajl_free_error(handle, (unsigned char *) error);
            goto parse;
    }
    char *type = "background";
    if (request.type == REQUEST_TYPE_NORMAL) type = "normal";
    else if (request.type == REQUEST_TYPE_URGENT) type = "urgent";
    syslog(LOG_INFO, "Received %s request %llu to notify %s", type, request.id, request.user);
parse:
    yajl_free(handle);
    free(request.user);
    free(request.collapse_id);
    free(request.payload);
}

static int request_yajl_null(void *data) {
    struct request *request = data;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    return 1;
}

static int request_yajl_boolean(void *data, int value) {
    (void) value;
    struct request *request = data;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    return 1;
}

static int request_yajl_integer(void *data, long long value) {
    struct request *request = data;
    if (request->state == REQUEST_STATE_EXPIRATION) request->expiration = value;
    else if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    return 1;
}

static int request_yajl_double(void *data, double value) {
    (void) value;
    struct request *request = data;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    return 1;
}

static int request_yajl_string(void *data, unsigned char const *value, size_t len) {
    struct request *request = data;
    switch (request->state) {
        case REQUEST_STATE_TYPE:
            if (!strncmp((char *) value, "background", len)) request->type = REQUEST_TYPE_BACKGROUND;
            else if (!strncmp((char *) value, "normal", len)) request->type = REQUEST_TYPE_NORMAL;
            else if (!strncmp((char *) value, "urgent", len)) request->type = REQUEST_TYPE_URGENT;
            else return 0;
            break;
        case REQUEST_STATE_USER:
            free(request->user);
            request->user = strndup((char *) value, len);
            if (!request->user) request->state = REQUEST_STATE_MEMORY;
            break;
        case REQUEST_STATE_COLLAPSE_ID:
            free(request->collapse_id);
            request->collapse_id = strndup((char *) value, len);
            if (!request->collapse_id) request->state = REQUEST_STATE_MEMORY;
            break;
        default:
            if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    }
    if (request->state == REQUEST_STATE_MEMORY) return 0;
    return 1;
}

static int request_yajl_start_map(void *data) {
    struct request *request = data;
    if (request->state == REQUEST_STATE_NONE) return 1;
    if (request->state < REQUEST_STATE_PAYLOAD) return 0;
    ++ request->state;
    return 1;
}

static int request_yajl_map_key(void *data, unsigned char const *key, size_t len) {
    struct request *request = data;
    if (request->state > REQUEST_STATE_PAYLOAD) return 1;
    if (len == sizeof "type" - 1 && !strncmp((char *) key, "type", len)) request->state = REQUEST_STATE_TYPE;
    else if (len == sizeof "expiration" - 1 && !strncmp((char *) key, "expiration", len)) request->state = REQUEST_STATE_EXPIRATION;
    else if (len == sizeof "user" - 1 && !strncmp((char *) key, "user", len)) request->state = REQUEST_STATE_USER;
    else if (len == sizeof "collapse_id" - 1 && !strncmp((char *) key, "collapse_id", len)) request->state = REQUEST_STATE_COLLAPSE_ID;
    else if (len == sizeof "payload" - 1 && !strncmp((char *) key, "payload", len)) request->state = REQUEST_STATE_PAYLOAD;
    else return 0;
    return 1;
}

static int request_yajl_end_map(void *data) {
    struct request *request = data;
    if (request->state > REQUEST_STATE_PAYLOAD) {
        -- request->state;
        return 1;
    }
    if (request->state == REQUEST_STATE_NONE) return 0;
    if (request->expiration < 0) return 0;
    if (!request->user) return 0;
    if (!request->collapse_id) return 0;
    return 1;
}

static int request_yajl_start_array(void *data) {
    struct request *request = data;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    ++ request->state;
    return 1;
}

static int request_yajl_end_array(void *data) {
    struct request *request = data;
    if (request->state <= REQUEST_STATE_PAYLOAD) return 0;
    -- request->state;
    return 1;
}
