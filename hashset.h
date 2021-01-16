#ifndef HASHSET
#define HASHSET

typedef struct hashset hashset_t;
typedef size_t (*hashset_hash_t)(void const *key);
typedef int (*hashset_compare_t)(void const *left, void const *right);

hashset_t *hashset_create(hashset_hash_t hash, hashset_compare_t compare);
void hashset_destroy(hashset_t *hashset);
size_t hashset_reserve(hashset_t *hashset, size_t cap);

void *hashset_insert(hashset_t *hashset, void *value);
void *hashset_update(hashset_t *hashset, void *value);
void *hashset_select(hashset_t *hashset, void const *key);
void *hashset_delete(hashset_t *hashset, void const *key);

size_t hashset_count(hashset_t *hashset);
void hashset_wipe(hashset_t *hashset);

#endif
