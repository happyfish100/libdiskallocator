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

#ifndef _DA_BINLOG_FD_CACHE_H
#define _DA_BINLOG_FD_CACHE_H

#include "fastcommon/fc_list.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/shared_func.h"
#include "../../global.h"
#include "binlog_types.h"

typedef struct da_binlog_id_fd_pair {
    uint64_t id;
    int fd;
} DABinlogIdFDPair;

typedef struct da_binlog_fd_cache_entry {
    DABinlogIdFDPair pair;
    struct fc_list_head dlink;
    struct da_binlog_fd_cache_entry *next;  //for hashtable
} DABinlogFDCacheEntry;

typedef struct {
    DABinlogFDCacheEntry **buckets;
    unsigned int size;
} DABinlogFDCacheHashtable;

typedef struct {
    char subdir_name[64];
    DABinlogFDCacheHashtable htable;
    int open_flags;
    int max_idle_time;
    struct {
        int capacity;
        int count;
        struct fc_list_head head;
    } lru;
    struct fast_mblock_man allocator;
} DABinlogFDCacheContext;


#ifdef __cplusplus
extern "C" {
#endif

    int da_binlog_fd_cache_init(DABinlogFDCacheContext *cache_ctx,
            const char *subdir_name, const int open_flags,
            const int max_idle_time, const int capacity);

    //return fd, < 0 for error
    int da_binlog_fd_cache_get(DABinlogFDCacheContext *cache_ctx,
            const uint64_t id);

    int da_binlog_fd_cache_remove(DABinlogFDCacheContext *cache_ctx,
            const uint64_t id);

    void da_binlog_fd_cache_clear(DABinlogFDCacheContext *cache_ctx);

    static inline int da_binlog_fd_cache_filename(
            DABinlogFDCacheContext *cache_ctx, const uint64_t id,
            char *full_filename, const int size)
    {
        int path_index;

        path_index = id % DA_BINLOG_SUBDIRS;
        snprintf(full_filename, size, "%s/%s/%02X/%02X/binlog.%08"PRIX64,
                DA_DATA_PATH_STR, cache_ctx->subdir_name, path_index,
                path_index, id);
        return 0;
    }

#ifdef __cplusplus
}
#endif

#endif
