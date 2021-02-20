#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>
#include <event2/event.h>

#include "notification.h"
#include "dispatch.h"
#include "request.h"

static yajl_callbacks request_yajl_callbacks;
static yajl_gen request_yajl_gen;
static size_t request_yajl_payload_depth;

static int request_yajl_root_map_start(void *arg);
static int request_yajl_root_map_key(void *arg, unsigned char const *key, size_t len);
static int request_yajl_root_map_end(void *arg);
static int request_yajl_root_map_value_groups_array_start(void *arg);
static int request_yajl_root_map_value_groups_array_string(void *arg, unsigned char const *value, size_t len);
static int request_yajl_root_map_value_groups_array_end(void *arg);
static int request_yajl_root_map_value_type_string(void *arg, unsigned char const *value, size_t len);
static int request_yajl_root_map_value_expiration_integer(void *arg, long long value);
static int request_yajl_root_map_value_key_string(void *arg, unsigned char const *value, size_t len);
static int request_yajl_root_map_value_payload__null(void *arg);
static int request_yajl_root_map_value_payload__boolean(void *arg, int value);
static int request_yajl_root_map_value_payload__integer(void *arg, long long value);
static int request_yajl_root_map_value_payload__double(void *arg, double value);
static int request_yajl_root_map_value_payload__string(void *arg, unsigned char const *value, size_t len);
static int request_yajl_root_map_value_payload__map_start(void *arg);
static int request_yajl_root_map_value_payload__map_key(void *arg, unsigned char const *key, size_t len);
static int request_yajl_root_map_value_payload__map_end(void *arg);
static int request_yajl_root_map_value_payload__array_start(void *arg);
static int request_yajl_root_map_value_payload__array_end(void *arg);
static void request_yajl_append(void *arg, char const *chunk, size_t len);

void request_process(char const *json, size_t len) {
    if (notification_prepare() < 0) return;
    request_yajl_callbacks = (yajl_callbacks) {.yajl_start_map = request_yajl_root_map_start};
    request_yajl_payload_depth = 0;
    yajl_handle yajl = yajl_alloc(&request_yajl_callbacks, NULL, NULL);
    if (!yajl) {
        syslog(LOG_WARNING, "Dropping notification request #%llu due to insufficient memory for the parser", notification_get_request_id(NULL));
        goto yajl;
    }
    yajl_status status = yajl_parse(yajl, (unsigned char *) json, len);
    if (status == yajl_status_ok) status = yajl_complete_parse(yajl);
    if (request_yajl_gen) yajl_gen_free(request_yajl_gen);
    yajl_free(yajl);
    if (status != yajl_status_ok) {
        syslog(LOG_WARNING, "Dropping notification request #%llu due to a parser error", notification_get_request_id(NULL));
        goto parse;
    }
    notification_queue_t *queue = notification_gen_queue();
    if (queue) dispatch_enqueue(queue);
    return;
parse:
yajl:
    notification_abort();
}

static int request_yajl_root_map_start(void *arg) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_map_key = request_yajl_root_map_key
    };
    return 1;
}

static int request_yajl_root_map_key(void *arg, unsigned char const *key, size_t len) {
    (void) arg;
    if (len == sizeof "groups" - 1 && strncmp((char const *) key, "groups", len) == 0) {
        request_yajl_callbacks = (yajl_callbacks) {
            .yajl_start_array = request_yajl_root_map_value_groups_array_start
        };
        return 1;
    }
    if (len == sizeof "type" - 1 && strncmp((char const *) key, "type", len) == 0) {
        request_yajl_callbacks = (yajl_callbacks) {
            .yajl_string = request_yajl_root_map_value_type_string
        };
        return 1;
    }
    if (len == sizeof "expiration" - 1 && strncmp((char const *) key, "expiration", len) == 0) {
        request_yajl_callbacks = (yajl_callbacks) {
            .yajl_integer = request_yajl_root_map_value_expiration_integer
        };
        return 1;
    }
    if (len == sizeof "key" - 1 && strncmp((char const *) key, "key", len) == 0) {
        request_yajl_callbacks = (yajl_callbacks) {
            .yajl_string = request_yajl_root_map_value_key_string
        };
        return 1;
    }
    if (len == sizeof "payload" - 1 && strncmp((char const *) key, "payload", len) == 0) {
        request_yajl_callbacks = (yajl_callbacks) {
            .yajl_start_map = request_yajl_root_map_value_payload__map_start
        };
        return 1;
    }
    return 0;
}

static int request_yajl_root_map_end(void *arg) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {.yajl_null = NULL};
    return 1;
}

static int request_yajl_root_map_value_groups_array_start(void *arg) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_string = request_yajl_root_map_value_groups_array_string
    };
    if (notification_add_group(NULL, 0) < 0) return 0;
    return 1;
}

static int request_yajl_root_map_value_groups_array_string(void *arg, unsigned char const *value, size_t len) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_string = request_yajl_root_map_value_groups_array_string,
        .yajl_end_array = request_yajl_root_map_value_groups_array_end
    };
    if (notification_add_group((char const *) value, len) < 0) return 0;
    return 1;
}

static int request_yajl_root_map_value_groups_array_end(void *arg) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_map_key = request_yajl_root_map_key,
        .yajl_end_map = request_yajl_root_map_end
    };
    return 1;
}

static int request_yajl_root_map_value_type_string(void *arg, unsigned char const *value, size_t len) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_map_key = request_yajl_root_map_key,
        .yajl_end_map = request_yajl_root_map_end
    };
    if (len == sizeof "background" - 1 && strncmp((char const *) value, "background", len) == 0) {
        notification_set_type(NOTIFICATION_TYPE_BACKGROUND);
        return 1;
    }
    if (len == sizeof "normal" - 1 && strncmp((char const *) value, "normal", len) == 0) {
        notification_set_type(NOTIFICATION_TYPE_NORMAL);
        return 1;
    }
    if (len == sizeof "urgent" - 1 && strncmp((char const *) value, "urgent", len) == 0) {
        notification_set_type(NOTIFICATION_TYPE_URGENT);
        return 1;
    }
    return 0;
}

static int request_yajl_root_map_value_expiration_integer(void *arg, long long value) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_map_key = request_yajl_root_map_key,
        .yajl_end_map = request_yajl_root_map_end
    };
    notification_set_expiration(value);
    return 1;
}

static int request_yajl_root_map_value_key_string(void *arg, unsigned char const *value, size_t len) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_map_key = request_yajl_root_map_key,
        .yajl_end_map = request_yajl_root_map_end
    };
    if (notification_set_key((char const *) value, len) < 0) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__null(void *arg) {
    (void) arg;
    if (yajl_gen_null(request_yajl_gen) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__boolean(void *arg, int value) {
    (void) arg;
    if (yajl_gen_bool(request_yajl_gen, value) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__integer(void *arg, long long value) {
    (void) arg;
    if (yajl_gen_integer(request_yajl_gen, value) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__double(void *arg, double value) {
    (void) arg;
    if (yajl_gen_double(request_yajl_gen, value) != 1) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__string(void *arg, unsigned char const *value, size_t len) {
    (void) arg;
    if (yajl_gen_string(request_yajl_gen, value, len) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__map_start(void *arg) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_map_key = request_yajl_root_map_value_payload__map_key
    };
    if (!request_yajl_payload_depth) {
        notification_append_payload(NULL, 0);
        request_yajl_gen = yajl_gen_alloc(NULL);
        if (!request_yajl_gen) return 0;
        yajl_gen_config(request_yajl_gen, yajl_gen_print_callback, request_yajl_append, NULL);
    }
    ++ request_yajl_payload_depth;
    if (yajl_gen_map_open(request_yajl_gen) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__map_key(void *arg, unsigned char const *key, size_t len) {
    (void) arg;
    request_yajl_callbacks = (yajl_callbacks) {
        .yajl_null = request_yajl_root_map_value_payload__null,
        .yajl_boolean = request_yajl_root_map_value_payload__boolean,
        .yajl_integer = request_yajl_root_map_value_payload__integer,
        .yajl_double = request_yajl_root_map_value_payload__double,
        .yajl_string = request_yajl_root_map_value_payload__string,
        .yajl_start_map = request_yajl_root_map_value_payload__map_start,
        .yajl_map_key = request_yajl_root_map_value_payload__map_key,
        .yajl_end_map = request_yajl_root_map_value_payload__map_end,
        .yajl_start_array = request_yajl_root_map_value_payload__array_start,
        .yajl_end_array = request_yajl_root_map_value_payload__array_end
    };
    if (yajl_gen_string(request_yajl_gen, key, len) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__map_end(void *arg) {
    (void) arg;
    if (yajl_gen_map_close(request_yajl_gen) != yajl_gen_status_ok) return 0;
    -- request_yajl_payload_depth;
    if (!request_yajl_payload_depth) {
        request_yajl_callbacks = (yajl_callbacks) {
            .yajl_map_key = request_yajl_root_map_key,
            .yajl_end_map = request_yajl_root_map_end
        };
        yajl_gen_free(request_yajl_gen);
        request_yajl_gen = NULL;
    }
    return 1;
}

static int request_yajl_root_map_value_payload__array_start(void *arg) {
    (void) arg;
    if (yajl_gen_array_open(request_yajl_gen) != yajl_gen_status_ok) return 0;
    return 1;
}

static int request_yajl_root_map_value_payload__array_end(void *arg) {
    (void) arg;
    if (yajl_gen_array_close(request_yajl_gen) != yajl_gen_status_ok) return 0;
    return 1;
}

static void request_yajl_append(void *arg, char const *chunk, size_t len) {
    (void) arg;
    notification_append_payload(chunk, len);
}
