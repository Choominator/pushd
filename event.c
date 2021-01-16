#include <stdlib.h>
#include <signal.h>

#include "event.h"
#include "hashset.h"

struct event_bucket;

struct event {
    unsigned long long transaction;
    event_handler_t handler;
    void *data;
    struct event *next, *prev;
    struct event_bucket *bucket;
    size_t ref_count;
};

struct event_bucket {
    int signum;
    struct event *head, *tail;
};

static hashset_t *event_set = NULL;
static unsigned long long event_transaction = 0;
static unsigned long long event_commit = 0;

static void event_handler(int signum, siginfo_t *info, void *ucontext);
static size_t event_hash(void const *key);
static int event_compare(void const *left, void const *right);

void event_loop(void) {
    sigset_t sigmask;
    sigemptyset(&sigmask);
    event_commit = event_transaction;
    while (event_set) sigsuspend(&sigmask);
}

event_t *event_subscribe(int signum, event_handler_t handler, void *data) {
    if (!event_set) {
        event_set = hashset_create(event_hash, event_compare);
        if (!event_set) return NULL;
    }
    struct event_bucket *bucket = hashset_select(event_set, &signum);
    if (!bucket) {
        bucket = malloc(sizeof *bucket);
        if (!bucket) goto bucket;
        *bucket = (struct  event_bucket) {.signum = signum};
        if (!hashset_insert(event_set, bucket)) goto node;
    }
    struct event *event = malloc(sizeof *event);
    if (!event) goto event;
    if (event_transaction == event_commit) ++ event_transaction;
    *event = (struct event) {.transaction = event_transaction, .handler = handler, .data = data, .prev = bucket->tail, .bucket = bucket, .ref_count = 1};
    if (bucket->tail) bucket->tail->next = event;
    else bucket->head = event;
    bucket->tail = event;
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, signum);
    sigprocmask(SIG_BLOCK, &sigset, NULL);
    struct sigaction action = {.sa_sigaction = event_handler, .sa_flags = SA_SIGINFO};
    sigfillset(&action.sa_mask);
    if (sigaction(signum, &action, NULL) < 0) goto signal;
    return event;
signal:
    if (event->next) event->next->prev = event->prev;
    else bucket->tail = event->prev;
    if (event->prev) event->prev->next = event->next;
    else bucket->head = event->next;
    free(event);
event:
    if (!bucket->head) hashset_delete(event_set, bucket);
node:
    if (!bucket->head) free(bucket);
bucket:
    if (!hashset_count(event_set)) {
        hashset_destroy(event_set);
        event_set = NULL;
    }
    return NULL;
}

void event_retain(event_t *event) {
    ++ event->ref_count;
}

void event_release(event_t *event) {
    -- event->ref_count;
    if (event->ref_count) return;
    struct event_bucket *bucket = event->bucket;
    if (event->next) event->next->prev = event->prev;
    else bucket->tail = event->prev;
    if (event->prev) event->prev->next = event->next;
    else bucket->head = event->next;
    free(event);
    if (bucket->head) return;
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigaction(bucket->signum, &action, NULL);
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, bucket->signum);
    sigprocmask(SIG_UNBLOCK, &sigset, NULL);
    hashset_delete(event_set, bucket);
    free(bucket);
    if (hashset_count(event_set)) return;
    hashset_destroy(event_set);
    event_set = NULL;
}

static void event_handler(int signum, siginfo_t *info, void *ucontext) {
    (void) ucontext;
    struct event_bucket *bucket = hashset_select(event_set, &signum);
    for (struct event *current = bucket->head; current; current = current->next) if (current->transaction <= event_commit) event_retain(current);
    for (struct event *current = bucket->head, *next; current; current = next) {
        next = current->next;
        if (current->transaction > event_commit) continue;
        current->handler(current, info, current->data);
        event_release(current);
    }
    event_commit = event_transaction;
}

static size_t event_hash(void const *key) {
    return *(int const *) key;
}

static int event_compare(void const *left, void const *right) {
    int const *l = left;
    int const *r = right;
    if (*l < *r) return 1;
    if (*l > *r) return -1;
    return 0;
}
