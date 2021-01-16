#include <stdlib.h>
#include <string.h>

#include "hashset.h"

struct hashset_element;

struct hashset {
    struct hashset_element **buckets, *first, *last;
    size_t bucket_count, total_count;
    hashset_hash_t hash;
    hashset_compare_t compare;
};

struct hashset_element {
    struct hashset_element *bucket_next, *next, *prev;
    void *value;
};

static size_t hashset_next_prime(size_t value);
static int hashset_find(struct hashset *hashset, void const *key, struct hashset_element ***bucket);
static void hashset_rehash(struct hashset *hashset);

hashset_t *hashset_create(hashset_hash_t hash, hashset_compare_t compare) {
    struct hashset *hashset = malloc(sizeof *hashset);
    if (!hashset) goto hashset;
    *hashset = (struct hashset) {.hash = hash, .compare = compare};
    if (!hashset_reserve(hashset, 0)) goto buckets;
    return hashset;
buckets:
    free(hashset);
hashset:
    return NULL;
}

void hashset_destroy(hashset_t *hashset) {
    if (hashset->total_count) hashset_wipe(hashset);
    free(hashset->buckets);
    free(hashset);
}

size_t hashset_reserve(hashset_t *hashset, size_t cap) {
    struct hashset base = *hashset;
    if (cap <= base.total_count) cap = base.total_count;;
    cap *= 4 / 3;
    size_t bucket_count = hashset_next_prime(cap);
    if (bucket_count == base.bucket_count) return bucket_count;
    base.bucket_count = bucket_count;
    base.buckets = realloc(base.buckets, sizeof *base.buckets * bucket_count);
    if (!base.buckets) return hashset->bucket_count;
    hashset_rehash(&base);
    *hashset = base;
    return base.bucket_count;
}

void *hashset_insert(hashset_t *hashset, void *value) {
    struct hashset base = *hashset;
    struct hashset_element **bucket;
    if (hashset_find(&base, value, &bucket)) return (*bucket)->value;
    struct hashset_element *current = malloc(sizeof *current);
    if (!current) return NULL;
    *current = (struct hashset_element) {.value = value, .bucket_next = *bucket, .prev = base.last};
    base.last = current;
    if (current->prev) current->prev->next = current;
    else base.first = current;
    *bucket = current;
    ++ base.total_count;
    hashset_reserve(&base, 0);
    *hashset = base;
    return value;
}

void *hashset_update(hashset_t *hashset, void *value) {
    struct hashset_element **bucket;
    if (!hashset_find(hashset, value, &bucket)) return NULL;
    void *oldvalue = (*bucket)->value;
    (*bucket)->value = value;
    return oldvalue;
}

void *hashset_select(hashset_t *hashset, void const *key) {
    struct hashset_element **bucket;
    if (!hashset_find(hashset, key, &bucket)) return NULL;
    return (*bucket)->value;
}

void *hashset_delete(hashset_t *hashset, void const *key) {
    struct hashset_element **bucket;
    if (!hashset_find(hashset, key, &bucket)) return NULL;
    struct hashset_element *current = *bucket;
    *bucket = current->bucket_next;
    struct hashset base = *hashset;
    -- base.total_count;
    if (current->next) current->next->prev = current->prev;
    else base.last = current->prev;
    if (current->prev) current->prev->next = current->next;
    else base.first = current->next;
    void *value = current->value;
    free(current);
    *hashset = base;
    return value;
}

size_t hashset_count(hashset_t *hashset) {
    return hashset->total_count;
}

void hashset_wipe(hashset_t *hashset) {
    struct hashset base = *hashset;
    struct hashset_element *current = base.first;
    while (current) {
        struct hashset_element *next = current->next;
        free(current);
        current = next;
    }
    base.total_count = 0;
    base.first = base.last = NULL;
    memset(base.buckets, 0, sizeof *base.buckets * base.bucket_count);
    *hashset = base;
}

static size_t hashset_next_prime(size_t value) {
    static size_t const primes[] = {3, 7, 13, 29, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, 98317, 196613};
    size_t const *head = primes, *tail = primes + sizeof primes / sizeof *primes, *current = NULL;
    while (tail - head > 1) {
        current = head + ((tail - head) >> 1);
        if (*current == value) break;
        else if (*current < value) head = current;
        else tail = current;
    }
    return *current;
}

static int hashset_find(hashset_t *hashset, void const *key, struct hashset_element ***bucket) {
    struct hashset base = *hashset;
    size_t index = base.hash(key) % base.bucket_count;
    *bucket = base.buckets + index;
    for (struct hashset_element *current = **bucket, *prev = NULL; current; prev = current, current = current->bucket_next) {
        if (base.compare(current->value, key) != 0) continue;
        if (!prev) return 1;
        prev->bucket_next = current->bucket_next;
        current->bucket_next = **bucket;
        **bucket = current;
        return 1;
    }
    return 0;
}

static void hashset_rehash(hashset_t *hashset) {
    struct hashset base = *hashset;
    if (!base.buckets) return;
    memset(base.buckets, 0, sizeof *base.buckets * base.bucket_count);
    for (struct hashset_element *current = base.first; current; current = current->next) {
        size_t index = base.hash(current->value) % base.bucket_count;
        current->bucket_next = base.buckets[index];
        base.buckets[index] = current;
    }
    *hashset = base;
}
