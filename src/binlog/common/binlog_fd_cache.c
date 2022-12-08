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
#include "binlog_fd_cache.h"

static bool subdir_exists(const char *subdir_name, const int subdir_index)
{
    char filepath[PATH_MAX];

    snprintf(filepath, sizeof(filepath), "%s/%s/%02X/%02X",
            DA_DATA_PATH_STR, subdir_name, subdir_index, subdir_index);
    return isDir(filepath);
}

static int check_make_subdirs(const char *subdir_name)
{
    int result;
    int i, k;
    char filepath1[PATH_MAX];
    char filepath2[PATH_MAX];

    snprintf(filepath1, sizeof(filepath1), "%s/%s",
            DA_DATA_PATH_STR, subdir_name);
    if ((result=fc_check_mkdir(filepath1, 0755)) != 0) {
        return result;
    }

    if (subdir_exists(subdir_name, 0) && subdir_exists(
                subdir_name, DA_BINLOG_SUBDIRS - 1))
    {
        return 0;
    }

    for (i=0; i<DA_BINLOG_SUBDIRS; i++) {
        snprintf(filepath1, sizeof(filepath1), "%s/%s/%02X",
                DA_DATA_PATH_STR, subdir_name, i);
        if ((result=fc_check_mkdir(filepath1, 0755)) != 0) {
            return result;
        }

        for (k=0; k<DA_BINLOG_SUBDIRS; k++) {
            snprintf(filepath2, sizeof(filepath2),
                    "%s/%02X", filepath1, k);
            if ((result=fc_check_mkdir(filepath2, 0755)) != 0) {
                return result;
            }
        }
    }

    return 0;
}

static int init_htable_and_allocator(DABinlogFDCacheContext
        *cache_ctx, const int capacity)
{
    int bytes;
    int alloc_elements_once;
    unsigned int *prime_capacity;

    if ((prime_capacity=fc_hash_get_prime_capacity(capacity)) != NULL) {
        cache_ctx->htable.size = *prime_capacity;
    } else {
        cache_ctx->htable.size = capacity;
    }

    bytes = sizeof(DABinlogFDCacheEntry *) * cache_ctx->htable.size;
    cache_ctx->htable.buckets = (DABinlogFDCacheEntry **)fc_malloc(bytes);
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
    return fast_mblock_init_ex1(&cache_ctx->allocator,
            "binlog-fd-cache", sizeof(DABinlogFDCacheEntry),
            alloc_elements_once, 0, NULL, NULL, false);
}

int da_binlog_fd_cache_init(DABinlogFDCacheContext *cache_ctx,
        const char *subdir_name, const int open_flags,
        const int max_idle_time, const int capacity)
{
    int result;

    if ((result=init_htable_and_allocator(cache_ctx, capacity)) != 0) {
        return result;
    }

    snprintf(cache_ctx->subdir_name, sizeof(cache_ctx->subdir_name),
            "%s", subdir_name);
    if ((result=check_make_subdirs(cache_ctx->subdir_name)) != 0) {
        return result;
    }

    cache_ctx->open_flags = open_flags;
    cache_ctx->max_idle_time = max_idle_time;
    cache_ctx->lru.count = 0;
    cache_ctx->lru.capacity = capacity;
    FC_INIT_LIST_HEAD(&cache_ctx->lru.head);
    return 0;
}

static int fd_cache_get(DABinlogFDCacheContext *cache_ctx,
        const uint64_t id)
{
    DABinlogFDCacheEntry **bucket;
    DABinlogFDCacheEntry *entry;

    bucket = cache_ctx->htable.buckets + id % cache_ctx->htable.size;
    if (*bucket == NULL) {
        return -1;
    }
    if ((*bucket)->pair.id == id) {
        entry = *bucket;
    } else {
        entry = (*bucket)->next;
        while (entry != NULL) {
            if (entry->pair.id == id) {
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

static inline void fd_cache_remove(DABinlogFDCacheContext *cache_ctx,
        DABinlogFDCacheEntry *entry)
{
    close(entry->pair.fd);
    entry->pair.fd = -1;

    fc_list_del_init(&entry->dlink);
    fast_mblock_free_object(&cache_ctx->allocator, entry);
    cache_ctx->lru.count--;
}

int da_binlog_fd_cache_remove(DABinlogFDCacheContext *cache_ctx,
        const uint64_t id)
{
    DABinlogFDCacheEntry **bucket;
    DABinlogFDCacheEntry *previous;
    DABinlogFDCacheEntry *entry;

    bucket = cache_ctx->htable.buckets + id % cache_ctx->htable.size;
    if (*bucket == NULL) {
        return ENOENT;
    }

    previous = NULL;
    entry = *bucket;
    while (entry != NULL) {
        if (entry->pair.id == id) {
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

    fd_cache_remove(cache_ctx, entry);
    return 0;
}

void da_binlog_fd_cache_clear(DABinlogFDCacheContext *cache_ctx)
{
    DABinlogFDCacheEntry **bucket;
    DABinlogFDCacheEntry **end;
    DABinlogFDCacheEntry *entry;
    DABinlogFDCacheEntry *deleted;
    int count = 0;

    end = cache_ctx->htable.buckets + cache_ctx->htable.size;
    for (bucket=cache_ctx->htable.buckets; bucket<end; bucket++) {
        if (*bucket == NULL) {
            continue;
        }

        entry = *bucket;
        do {
            deleted = entry;
            entry = entry->next;
            fd_cache_remove(cache_ctx, deleted);
            ++count;
        } while (entry != NULL);

        *bucket = NULL;
    }
}

static int fd_cache_add(DABinlogFDCacheContext *cache_ctx,
        const uint64_t id, const int fd)
{
    DABinlogFDCacheEntry **bucket;
    DABinlogFDCacheEntry *entry;

    if (cache_ctx->lru.count >= cache_ctx->lru.capacity) {
        if ((entry=fc_list_first_entry(&cache_ctx->lru.head,
                        DABinlogFDCacheEntry, dlink)) != NULL)
        {
            da_binlog_fd_cache_remove(cache_ctx, entry->pair.id);
        }
    }

    entry = (DABinlogFDCacheEntry *)fast_mblock_alloc_object(
            &cache_ctx->allocator);
    if (entry == NULL) {
        return ENOMEM;
    }

    entry->pair.id = id;
    entry->pair.fd = fd;
    bucket = cache_ctx->htable.buckets + id % cache_ctx->htable.size;
    entry->next = *bucket;
    *bucket = entry;

    fc_list_add_tail(&entry->dlink, &cache_ctx->lru.head);
    cache_ctx->lru.count++;
    return 0;
}

static inline int open_file(DABinlogFDCacheContext *cache_ctx,
        const uint64_t id)
{
    int fd;
    int result;
    char full_filename[PATH_MAX];

    if ((result=da_binlog_fd_cache_filename(cache_ctx, id,
                    full_filename, sizeof(full_filename))) != 0)
    {
        return -1 * result;
    }

    if ((fd=open(full_filename, cache_ctx->open_flags, 0755)) < 0) {
        result = errno != 0 ? errno : ENOENT;
        logError("file: "__FILE__", line: %d, "
                "open file %s fail, errno: %d, error info: %s",
                __LINE__, full_filename, result, strerror(result));
        return -1 * result;
    }

    return fd;
}

int da_binlog_fd_cache_get(DABinlogFDCacheContext *cache_ctx,
        const uint64_t id)
{
    int fd;
    int result;

    if ((fd=fd_cache_get(cache_ctx, id)) >= 0) {
        return fd;
    }

    if ((fd=open_file(cache_ctx, id)) < 0) {
        return fd;
    }

    if ((result=fd_cache_add(cache_ctx, id, fd)) == 0) {
        return fd;
    } else {
        close(fd);
        return -1 * result;
    }
}
