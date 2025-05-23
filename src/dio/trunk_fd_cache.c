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
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_mblock.h"
#include "sf/sf_global.h"
#include "trunk_fd_cache.h"

int da_trunk_fd_cache_init(DATrunkFDCacheContext *cache_ctx, const int capacity)
{
    int result;
    int bytes;
    int alloc_elements_once;
    unsigned int *prime_capacity;

    if ((prime_capacity=fc_hash_get_prime_capacity(capacity)) != NULL) {
        cache_ctx->htable.size = *prime_capacity;
    } else {
        cache_ctx->htable.size = capacity;
    }

    bytes = sizeof(DATrunkFDCacheEntry *) * cache_ctx->htable.size;
    cache_ctx->htable.buckets = (DATrunkFDCacheEntry **)fc_malloc(bytes);
    if (cache_ctx->htable.buckets == NULL) {
        return ENOMEM;
    }
    memset(cache_ctx->htable.buckets, 0, bytes);

    if (capacity < 1024) {
        alloc_elements_once = 512;
    } else if (capacity < 2 * 1024) {
        alloc_elements_once = 1 * 1024;
    } else if (capacity < 4 * 1024) {
        alloc_elements_once = 2 * 1024;
    } else if (capacity < 8 * 1024) {
        alloc_elements_once = 4 * 1024;
    } else {
        alloc_elements_once = 8 * 1024;
    }
    if ((result=fast_mblock_init_ex1(&cache_ctx->allocator,
                    "trunk_fd_cache", sizeof(DATrunkFDCacheEntry),
                    alloc_elements_once, 0, NULL, NULL, false)) != 0)
    {
        return result;
    }

    cache_ctx->lru.count = 0;
    cache_ctx->lru.capacity = capacity;
    FC_INIT_LIST_HEAD(&cache_ctx->lru.head);
    return 0;
}

int da_trunk_fd_cache_get(DATrunkFDCacheContext *cache_ctx,
        const uint64_t trunk_id)
{
    DATrunkFDCacheEntry **bucket;
    DATrunkFDCacheEntry *entry;

    bucket = cache_ctx->htable.buckets + trunk_id % cache_ctx->htable.size;
    if (*bucket == NULL) {
        return -1;
    }
    if ((*bucket)->pair.trunk_id == trunk_id) {
        entry = *bucket;
    } else {
        entry = (*bucket)->next;
        while (entry != NULL) {
            if (entry->pair.trunk_id == trunk_id) {
                break;
            }

            entry = entry->next;
        }
    }

    if (entry != NULL) {
        fc_list_move_tail(&entry->dlink, &cache_ctx->lru.head);
        return entry->pair.fd;
    } else {
        return -1;
    }
}

int da_trunk_fd_cache_add(DATrunkFDCacheContext *cache_ctx,
        const uint64_t trunk_id, const int fd)
{
    DATrunkFDCacheEntry **bucket;
    DATrunkFDCacheEntry *entry;

    if (cache_ctx->lru.count >= cache_ctx->lru.capacity) {
        entry = fc_list_entry(cache_ctx->lru.head.next,
                DATrunkFDCacheEntry, dlink);
        da_trunk_fd_cache_delete(cache_ctx, entry->pair.trunk_id);
    }

    entry = (DATrunkFDCacheEntry *)fast_mblock_alloc_object(
            &cache_ctx->allocator);
    if (entry == NULL) {
        return ENOMEM;
    }

    entry->pair.trunk_id = trunk_id;
    entry->pair.fd = fd;

    bucket = cache_ctx->htable.buckets + trunk_id % cache_ctx->htable.size;
    entry->next = *bucket;
    *bucket = entry;

    fc_list_add_tail(&entry->dlink, &cache_ctx->lru.head);
    cache_ctx->lru.count++;
    return 0;
}

static inline void trunk_fd_cache_remove(DATrunkFDCacheContext *cache_ctx,
        DATrunkFDCacheEntry *entry)
{
    close(entry->pair.fd);
    entry->pair.fd = -1;

    fc_list_del_init(&entry->dlink);
    fast_mblock_free_object(&cache_ctx->allocator, entry);
    cache_ctx->lru.count--;
}

int da_trunk_fd_cache_delete(DATrunkFDCacheContext *cache_ctx,
        const uint64_t trunk_id)
{
    DATrunkFDCacheEntry **bucket;
    DATrunkFDCacheEntry *previous;
    DATrunkFDCacheEntry *entry;

    bucket = cache_ctx->htable.buckets + trunk_id % cache_ctx->htable.size;
    if (*bucket == NULL) {
        return ENOENT;
    }

    previous = NULL;
    entry = *bucket;
    while (entry != NULL) {
        if (entry->pair.trunk_id == trunk_id) {
            break;
        }

        previous = entry;
        entry = entry->next;
    }
    if (entry == NULL) {
        return ENOENT;
    }

    if (previous == NULL) {
        *bucket = entry->next;
    } else {
        previous->next = entry->next;
    }

    trunk_fd_cache_remove(cache_ctx, entry);
    return 0;
}

void da_trunk_fd_cache_clear(DATrunkFDCacheContext *cache_ctx)
{
    DATrunkFDCacheEntry **bucket;
    DATrunkFDCacheEntry **end;
    DATrunkFDCacheEntry *entry;
    DATrunkFDCacheEntry *deleted;

    end = cache_ctx->htable.buckets + cache_ctx->htable.size;
    for (bucket=cache_ctx->htable.buckets; bucket<end; bucket++) {
        if (*bucket == NULL) {
            continue;
        }

        entry = *bucket;
        do {
            deleted = entry;
            entry = entry->next;
            trunk_fd_cache_remove(cache_ctx, deleted);
        } while (entry != NULL);

        *bucket = NULL;
    }
}
