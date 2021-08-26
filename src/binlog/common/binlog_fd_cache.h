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

#ifndef _BINLOG_FD_CACHE_H
#define _BINLOG_FD_CACHE_H

#include "fastcommon/fc_list.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/shared_func.h"
#include "../../global.h"

typedef struct binlog_id_type_pair {
    uint64_t id;
    int type;
} BinlogIdTypePair;

typedef struct binlog_type_subdir_pair {
    int type;
    char subdir_name[64];
} BinlogTypeSubdirPair;

typedef struct binlog_type_subdir_array {
    BinlogTypeSubdirPair *pairs;
    int count;
} BinlogTypeSubdirArray;

typedef struct binlog_id_fd_pair {
    BinlogIdTypePair key;
    int fd;
} BinlogIdFDPair;

typedef struct binlog_fd_cache_entry {
    BinlogIdFDPair pair;
    struct fc_list_head dlink;
    struct binlog_fd_cache_entry *next;  //for hashtable
} BinlogFDCacheEntry;

typedef struct {
    BinlogFDCacheEntry **buckets;
    unsigned int size;
} BinlogFDCacheHashtable;

typedef struct {
    BinlogFDCacheHashtable htable;
    BinlogTypeSubdirArray type_subdir_array;
    int open_flags;
    int max_idle_time;
    struct {
        int capacity;
        int count;
        struct fc_list_head head;
    } lru;
    struct fast_mblock_man allocator;
} BinlogFDCacheContext;

#define BINLOG_ID_TYPE_EQUALS(key1, key2) \
    ((key1).id == (key2).id && (key1).type == (key2).type)

#ifdef __cplusplus
extern "C" {
#endif

    int binlog_fd_cache_init(BinlogFDCacheContext *cache_ctx,
            const BinlogTypeSubdirArray *type_subdir_array,
            const int open_flags, const int max_idle_time,
            const int capacity);

    //return fd, < 0 for error
    int binlog_fd_cache_get(BinlogFDCacheContext *cache_ctx,
            const BinlogIdTypePair *key);

    int binlog_fd_cache_remove(BinlogFDCacheContext *cache_ctx,
            const BinlogIdTypePair *key);

    static inline int binlog_fd_cache_filename(BinlogFDCacheContext
            *cache_ctx, const BinlogIdTypePair *key,
            char *full_filename, const int size)
    {
        int path_index;

        path_index = key->id % BINLOG_SUBDIRS;
        snprintf(full_filename, size, "%s/%s/%02X/%02X/binlog.%08"PRIX64,
                DATA_PATH_STR, cache_ctx->type_subdir_array.pairs
                [key->type].subdir_name, path_index, path_index, key->id);
        return 0;
    }

#ifdef __cplusplus
}
#endif

#endif