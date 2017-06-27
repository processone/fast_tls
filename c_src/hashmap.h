#ifndef HASHMAP_H
#define HASHMAP_H

#include <erl_nif.h>
#include <sys/types.h>
#include <stdint.h>

typedef uint32_t (*hashmap_hash_fun_t)(const void *el);
typedef int (*hashmap_cmp_fun_t)(const void *el1, const void *el2);

typedef struct hashmap_element {
  uint32_t hash;
  uint32_t used;
  char data[0];
} hashmap_element_t;

typedef struct hashmap {
  int capacity;
  int size;
  int data_size;
  hashmap_hash_fun_t hash_fun;
  hashmap_cmp_fun_t cmp_fun;
  void *data;
  ErlNifRWLock *lock;
} hashmap_t;

hashmap_t *hashmap_new(int initial_size, int data_size, hashmap_hash_fun_t hash_fun, hashmap_cmp_fun_t cmp_fun);
void hashmap_free(hashmap_t *map);
int hashmap_insert(hashmap_t *map, const void *data, void *old_data);
int hashmap_remove(hashmap_t *map, const void *data, void *old_data);
void *hashmap_lookup(hashmap_t *map, const void *data);
int hashmap_insert_no_lock(hashmap_t *map, const void *data, void *old_data);
int hashmap_remove_no_lock(hashmap_t *map, const void *data, void *old_data);
void *hashmap_lookup_no_lock(hashmap_t *map, const void *data);
void hashmap_lock(hashmap_t *map, int RWlock);
void hashmap_unlock(hashmap_t *map, int RWlock);

#endif
