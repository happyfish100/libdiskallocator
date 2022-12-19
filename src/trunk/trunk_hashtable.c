/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the GNU Affero General Public License, version 3
 * or later ("AGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <limits.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include "fastcommon/pthread_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fc_atomic.h"
#include "sf/sf_global.h"
#include "../global.h"
#include "trunk_hashtable.h"

typedef struct {
    DATrunkFileInfo **buckets;
    DATrunkFileInfo **end;
    int capacity;
    volatile int count;
} TrunkHashtable;

typedef struct {
    int count;
    pthread_mutex_t *locks;
} TrunkSharedLockArray;

typedef struct {
    TrunkHashtable htable;
    TrunkSharedLockArray lock_array;
} TrunkHtableContext;

static TrunkHtableContext trunk_htable_ctx;

int da_trunk_hashtable_count()
{
    return FC_ATOMIC_GET(trunk_htable_ctx.htable.count);
}

int da_trunk_hashtable_init()
{
    int result;
    int bytes;
    pthread_mutex_t *lock;
    pthread_mutex_t *end;

    trunk_htable_ctx.htable.capacity = 1403641;
    bytes = sizeof(DATrunkFileInfo *) * trunk_htable_ctx.htable.capacity;
    trunk_htable_ctx.htable.buckets = fc_malloc(bytes);
    if (trunk_htable_ctx.htable.buckets == NULL) {
        return ENOMEM;
    }
    memset(trunk_htable_ctx.htable.buckets, 0, bytes);
    trunk_htable_ctx.htable.end = trunk_htable_ctx.htable.buckets +
        trunk_htable_ctx.htable.capacity;

    trunk_htable_ctx.lock_array.count = 163;
    bytes = sizeof(pthread_mutex_t) * trunk_htable_ctx.lock_array.count;
    trunk_htable_ctx.lock_array.locks = fc_malloc(bytes);
    if (trunk_htable_ctx.lock_array.locks == NULL) {
        return ENOMEM;
    }

    end = trunk_htable_ctx.lock_array.locks +
        trunk_htable_ctx.lock_array.count;
    for (lock=trunk_htable_ctx.lock_array.locks; lock<end; lock++) {
        if ((result=init_pthread_lock(lock)) != 0) {
            return result;
        }
    }

    return 0;
}

void da_trunk_hashtable_destroy()
{
    if (trunk_htable_ctx.htable.buckets != NULL) {
        free(trunk_htable_ctx.htable.buckets);
        trunk_htable_ctx.htable.buckets = NULL;
    }

    if (trunk_htable_ctx.lock_array.locks != NULL) {
        pthread_mutex_t *lock;
        pthread_mutex_t *end;

        end = trunk_htable_ctx.lock_array.locks +
            trunk_htable_ctx.lock_array.count;
        for (lock=trunk_htable_ctx.lock_array.locks; lock<end; lock++) {
            pthread_mutex_destroy(lock);
        }

        free(trunk_htable_ctx.lock_array.locks);
        trunk_htable_ctx.lock_array.locks = NULL;
    }
}

#define TRUNK_HASHTABLE_SET_BUCKET_AND_LOCK(trunk_id) \
    uint32_t bucket_index;    \
    DATrunkFileInfo **bucket; \
    pthread_mutex_t *lock;    \
    \
    bucket_index = trunk_id % trunk_htable_ctx.htable.capacity; \
    bucket = trunk_htable_ctx.htable.buckets + bucket_index;    \
    lock = trunk_htable_ctx.lock_array.locks + bucket_index %   \
        trunk_htable_ctx.lock_array.count

int da_trunk_hashtable_add(DATrunkFileInfo *trunk)
{
    int result;
    DATrunkFileInfo *current;
    DATrunkFileInfo *previous;

    TRUNK_HASHTABLE_SET_BUCKET_AND_LOCK(trunk->id_info.id);

    result = 0;
    PTHREAD_MUTEX_LOCK(lock);
    previous = NULL;
    current = *bucket;
    while (current != NULL) {
        if (trunk->id_info.id < current->id_info.id) {
            break;
        } else if (trunk->id_info.id == current->id_info.id) {
            result = EEXIST;
            logError("file: "__FILE__", line: %d, "
                    "trunk id: %u already exist", __LINE__,
                    trunk->id_info.id);
            break;
        }

        previous = current;
        current = current->htable.next;
    }

    if (result == 0) {
        if (previous == NULL) {
            trunk->htable.next = *bucket;
            *bucket = trunk;
        } else {
            trunk->htable.next = current;
            previous->htable.next = trunk;
        }

        FC_ATOMIC_INC(trunk_htable_ctx.htable.count);
    }
    PTHREAD_MUTEX_UNLOCK(lock);

    return result;
}

DATrunkFileInfo *da_trunk_hashtable_get(const uint32_t trunk_id)
{
    DATrunkFileInfo *current;
    int result;

    TRUNK_HASHTABLE_SET_BUCKET_AND_LOCK(trunk_id);

    result = ENOENT;
    PTHREAD_MUTEX_LOCK(lock);
    current = *bucket;
    while (current != NULL) {
        if (trunk_id == current->id_info.id) {
            result = 0;
            break;
        } else if (trunk_id < current->id_info.id) {
            break;
        }

        current = current->htable.next;
    }
    PTHREAD_MUTEX_UNLOCK(lock);

    if (result == 0) {
        return current;
    } else {
        logError("file: "__FILE__", line: %d, "
                "trunk id: %u NOT exist",
                __LINE__, trunk_id);
        return NULL;
    }
}

void da_trunk_hashtable_iterator(DATrunkHashtableIterator *it,
        const bool need_lock)
{
    it->bucket = trunk_htable_ctx.htable.buckets;
    it->current = NULL;
    it->need_lock = need_lock;
}

DATrunkFileInfo *da_trunk_hashtable_next(DATrunkHashtableIterator *it)
{
    DATrunkFileInfo *trunk = NULL;
    pthread_mutex_t *lock = NULL;

    do {
        if (it->need_lock) {
            lock = trunk_htable_ctx.lock_array.locks + ((it->bucket -
                        trunk_htable_ctx.htable.buckets) %
                        trunk_htable_ctx.lock_array.count);
            PTHREAD_MUTEX_LOCK(lock);
        }

        if (it->current == NULL) {
            it->current = *(it->bucket);
        } else {
            it->current = it->current->htable.next;
        }

        if (it->need_lock) {
            PTHREAD_MUTEX_UNLOCK(lock);
        }

        if (it->current != NULL) {
            trunk = it->current;
            break;
        }
    } while (++(it->bucket) < trunk_htable_ctx.htable.end);

    return trunk;
}
