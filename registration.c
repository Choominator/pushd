#include <stdlib.h>
#include <string.h>

#include <event2/event.h>
#include <yajl/yajl_parse.h>

#include "logger.h"
#include "database.h"
#include "registration.h"

struct registration {
    enum {
        REGISTRATION_STATE_NONE,
        REGISTRATION_STATE_ROOT,
        REGISTRATION_STATE_GROUP,
        REGISTRATION_STATE_DEVICE
    } state;
    char *group, *device;
    size_t group_len, device_len;
};

static int registration_yajl_string(void *arg, unsigned char const *value, size_t len);
static int registration_yajl_start_map(void *arg);
static int registration_yajl_map_key(void *arg, unsigned char const *key, size_t len);
static int registration_yajl_end_map(void *arg);

static yajl_callbacks const registration_yajl_callbacks = {
    .yajl_string = registration_yajl_string,
    .yajl_start_map = registration_yajl_start_map,
    .yajl_map_key = registration_yajl_map_key,
    .yajl_end_map = registration_yajl_end_map
};

void registration_process(char const *json, size_t len) {
    struct registration registration = {.state = REGISTRATION_STATE_NONE};
    yajl_handle yajl = yajl_alloc(&registration_yajl_callbacks, NULL, &registration);
    if (!yajl) {
        logger_complain("Processing a registration request: Creating a JSON parser instance: %s", strerror(errno));
        return;
    }
    yajl_status status = yajl_parse(yajl, (unsigned char const *) json, len);
    if (status == yajl_status_ok) status = yajl_complete_parse(yajl);
    if (status != yajl_status_ok) {
        if (status == yajl_status_error) logger_complain("Processing a registration request: Parse error");
        goto parse;
    }
    if (!registration.group || !registration.device) {
        logger_complain("Processing a registration request: Erroneus data");
        goto data;
    }
    if (database_subscribe(registration.device, registration.device_len, registration.group, registration.group_len) < 0) {
        logger_complain("Processing a registration request");
        goto database;
    }
    logger_report("Processed a registration request to assign the device token %.*s to group %.*s", (int) registration.device_len, registration.device, (int) registration.group_len, registration.group);
database:
data:
    free(registration.group);
    free(registration.device);
parse:
    yajl_free(yajl);
}

static int registration_yajl_string(void *arg, unsigned char const *value, size_t len) {
    if (!len) goto empty;
    struct registration *registration = arg;
    switch (registration->state) {
        case REGISTRATION_STATE_GROUP:
            free(registration->group);
            registration->group = strndup((char const *) value, len);
            registration->group_len = len;
            if (!registration->group) goto copy;
            break;
        case REGISTRATION_STATE_DEVICE:
            free(registration->device);
            registration->device = strndup((char const *) value, len);
            registration->device_len = len;
            if (!registration->device) goto copy;
            break;
        default:
            break;
    }
    registration->state = REGISTRATION_STATE_ROOT;
    return 1;
copy:
    logger_complain("Processing a registration request: Copying a value: %s", strerror(errno));
    return 0;
empty:
    logger_complain("Processing a registration request: Empty string");
    return 0;
}

static int registration_yajl_start_map(void *arg) {
    struct registration *registration = arg;
    if (registration->state != REGISTRATION_STATE_NONE) goto parse;
    registration->state = REGISTRATION_STATE_ROOT;
    return 1;
parse:
    logger_complain("Processing a registration request: Parse error");
    return 0;
}

static int registration_yajl_map_key(void *arg, unsigned char const *key, size_t len) {
    struct registration *registration = arg;
    if (len == sizeof "group" - 1 && strncmp((char const *) key, "group", len) == 0) registration->state = REGISTRATION_STATE_GROUP;
    else if (len == sizeof "device" - 1 && strncmp((char const *) key, "device", len) == 0) registration->state = REGISTRATION_STATE_DEVICE;
    else goto key;
    return 1;
key:
    logger_complain("Processing a a registration request: Unknown key: %.*s", (int) len, (char const *) key);
    return 0;
}

static int registration_yajl_end_map(void *arg) {
    struct registration *registration = arg;
    registration->state = REGISTRATION_STATE_NONE;
    return 1;
}
