/*
 * Copyright (C) 2002-2017 ProcessOne, SARL. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "hashmap.h"
#include <string.h>
#include <stdio.h>
#include <openssl/err.h>

#define enif_alloc malloc
#define enif_free free
#define enif_realloc realloc

static uint32_t calc_index_for_hash(hashmap_t *map, uint32_t hash) {
  hash += (hash << 12);
  hash ^= (hash >> 22);
  hash += (hash << 4);
  hash ^= (hash >> 9);
  hash += (hash << 10);
  hash ^= (hash >> 2);
  hash += (hash << 7);
  hash ^= (hash >> 12);

  hash = (hash >> 3) * 2654435761;

  return hash % map->capacity;
}

static inline hashmap_element_t *get_el(hashmap_t *map, int idx)
{
  return (hashmap_element_t*)(map->data + ((sizeof(hashmap_element_t) + map->data_size) * idx));
}

hashmap_t *hashmap_new(int initial_size, int data_size, hashmap_hash_fun_t hash_fun, hashmap_cmp_fun_t cmp_fun)
{
  hashmap_t *map = (hashmap_t*)enif_alloc(sizeof(hashmap_t));
  if (!map)
    return NULL;

  map->data_size = data_size;
  map->capacity = initial_size;
  map->size = 0;
  map->hash_fun = hash_fun;
  map->cmp_fun = cmp_fun;

  map->data = enif_alloc((sizeof(hashmap_element_t) + data_size) * map->capacity);
  if (!map->data)
    goto fail_1;

  map->lock = enif_rwlock_create("hashmap_lock");
  if (!map->lock)
    goto fail_2;

  int i;
  for (i = 0; i < map->capacity; i++)
    get_el(map, i)->used = 0;

  return map;

 fail_2:
  enif_free(map->data);
 fail_1:
  enif_free(map);
  return NULL;
}

void hashmap_free(hashmap_t *map)
{
  if (!map)
    return;

  enif_rwlock_destroy(map->lock);
  enif_free(map->data);
  enif_free(map);
}

static int hashmap_do_insert(hashmap_t *map, uint32_t hash, const void *data, void *old_data)
{
  uint32_t index = calc_index_for_hash(map, hash);
  hashmap_element_t *el = get_el(map, index);

  while (el->used == 1 && (el->hash != hash || !map->cmp_fun(el->data, data))) {
    index = (index+1) % map->capacity;
    el = get_el(map, index);
  }

  int was_used = el->used == 1;

  if (was_used && old_data) {
    memcpy(old_data, el->data, map->data_size);
  }

  el->used = 1;
  el->hash = hash;
  memcpy(el->data, data, map->data_size);

  return was_used;
}

int hashmap_insert_no_lock(hashmap_t *map, const void *data, void *old_data)
{
  uint32_t hash = map->hash_fun(data);

  if (3*map->capacity < 4*map->size) {
    hashmap_element_t *data = enif_alloc(map->capacity*2*(sizeof(hashmap_element_t) + map->data_size));
    if (!data)
      return -1;

    hashmap_t old_map = *map;

    map->data = data;
    map->capacity = map->capacity*2;

    int i;
    for (i = 0; i < map->capacity; i++)
      get_el(map, i)->used = 0;

    for (i = 0; i < old_map.capacity; i++) {
      hashmap_element_t *el = get_el(&old_map, i);
      if (el->used == 1)
        hashmap_do_insert(map, el->hash, el->data, NULL);
    }
    enif_free(old_map.data);
  }

  int was_used = hashmap_do_insert(map, hash, data, old_data);
  if (!was_used)
    map->size++;

  return was_used;
}

int hashmap_remove_no_lock(hashmap_t *map, const void *data, void *old_data)
{
  uint32_t hash = map->hash_fun(data);

  uint32_t index = calc_index_for_hash(map, hash);
  hashmap_element_t *el = get_el(map, index);

  while (el->used && el->hash == hash && (el->used == 2 || !map->cmp_fun(el->data, data))) {
    index = (index+1) & map->capacity;
    el = get_el(map, index);
  }

  if (el->used == 1 && el->hash == hash) {
    el->used = 2;
    map->size--;

    if (old_data)
      memcpy(old_data, el->data, map->data_size);

    return 1;
  }

  return 0;
}

void *hashmap_lookup_no_lock(hashmap_t *map, const void *data)
{
  uint32_t hash = map->hash_fun(data);

  uint32_t index = calc_index_for_hash(map, hash);
  hashmap_element_t *el = get_el(map, index);

  while (el->used && el->hash == hash && !map->cmp_fun(el->data, data)) {
    index = (index+1) & map->capacity;
    el = get_el(map, index);
  }

  void *ret = NULL;
  if (el->used && el->hash == hash)
    ret = el->data;

  return ret;
}

int hashmap_insert(hashmap_t *map, const void *data, void *old_data)
{
  enif_rwlock_rwlock(map->lock);
  int ret = hashmap_insert_no_lock(map, data, old_data);
  enif_rwlock_rwunlock(map->lock);

  return ret;
}

int hashmap_remove(hashmap_t *map, const void *data, void *old_data)
{
  enif_rwlock_rwlock(map->lock);
  int ret = hashmap_remove_no_lock(map, data, old_data);
  enif_rwlock_rwunlock(map->lock);

  return ret;
}

void *hashmap_lookup(hashmap_t *map, const void *data)
{
  enif_rwlock_rlock(map->lock);
  void *ret = hashmap_lookup_no_lock(map, data);
  enif_rwlock_runlock(map->lock);

  return ret;
}

void hashmap_lock(hashmap_t *map, int RWlock)
{
  if (RWlock)
    enif_rwlock_rwlock(map->lock);
  else
    enif_rwlock_rlock(map->lock);
}

void hashmap_unlock(hashmap_t *map, int RWlock)
{
  if (RWlock)
    enif_rwlock_rwunlock(map->lock);
  else
    enif_rwlock_runlock(map->lock);
}
