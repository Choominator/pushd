#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <yajl/yajl_parse.h>

#include "database.h"
#include "registration.h"

struct registration {
    enum {
        REGISTRATION_STATE_NONE,
        REGISTRATION_STATE_MEMORY,
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
        syslog(LOG_WARNING, "Dropping registration request due to insufficient memory to parse it");
        return;
    }
    yajl_status status = yajl_parse(yajl, (unsigned char *) json, len);
    if (status == yajl_status_ok) status = yajl_complete_parse(yajl);
    if (status != yajl_status_ok) {
        if (registration.state != REGISTRATION_STATE_MEMORY) syslog(LOG_NOTICE, "Dropping registration request due to a parse error");
        else syslog(LOG_WARNING, "Dropping registration request due to insufficient memory to parse it");
        goto parse;
    }
    if (!registration.group || !registration.device) {
        syslog(LOG_NOTICE, "Dropping registration request due to missing data");
        goto data;
    }
    syslog(LOG_INFO, "Received registration request to assign the device token %s to group %s", registration.device, registration.group);
    database_subscribe(registration.device, registration.device_len, registration.group, registration.group_len);
data:
    free(registration.group);
    free(registration.device);
parse:
    yajl_free(yajl);
}


static int registration_yajl_string(void *arg, unsigned char const *value, size_t len) {
    if (!len) return 0;
    struct registration *registration = arg;
    switch (registration->state) {
        case REGISTRATION_STATE_GROUP:
            free(registration->group);
            registration->group = strndup((char const *) value, len);
            registration->group_len = len;
            if (!registration->group) registration->state = REGISTRATION_STATE_MEMORY;
            break;
        case REGISTRATION_STATE_DEVICE:
            free(registration->device);
            registration->device = strndup((char const *) value, len);
            registration->device_len = len;
            if (!registration->device) registration->state = REGISTRATION_STATE_MEMORY;
            break;
        default:
            return 0;
    }
    if (registration->state == REGISTRATION_STATE_MEMORY) return 0;
    registration->state = REGISTRATION_STATE_ROOT;
    return 1;
}

static int registration_yajl_start_map(void *arg) {
    struct registration *registration = arg;
    if (registration->state != REGISTRATION_STATE_NONE) return 0;
    registration->state = REGISTRATION_STATE_ROOT;
    return 1;
}

static int registration_yajl_map_key(void *arg, unsigned char const *key, size_t len) {
    struct registration *registration = arg;
    if (len == sizeof "group" - 1 && strncmp((char const *) key, "group", len) == 0) registration->state = REGISTRATION_STATE_GROUP;
    else if (len == sizeof "device" - 1 && strncmp((char const *) key, "device", len) == 0) registration->state = REGISTRATION_STATE_DEVICE;
    else return 0;
    return 1;
}

static int registration_yajl_end_map(void *arg) {
    struct registration *registration = arg;
    registration->state = REGISTRATION_STATE_NONE;
    return 1;
}
