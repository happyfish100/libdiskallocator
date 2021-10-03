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


#ifndef _TRUNK_FD_CACHE_H
#define _TRUNK_FD_CACHE_H

#include "fastcommon/fc_list.h"
#include "../storage_types.h"
#include "../trunk/trunk_allocator.h"
#include "../trunk/trunk_hashtable.h"

typedef struct trunk_id_fd_pair {
    uint32_t trunk_id;
    int fd;
} TrunkIdFDPair;

typedef struct trunk_fd_cache_entry {
    TrunkIdFDPair pair;
    struct fc_list_head dlink;
    struct trunk_fd_cache_entry *next;  //for hashtable
} TrunkFDCacheEntry;

typedef struct {
    TrunkFDCacheEntry **buckets;
    unsigned int size;
} TrunkFDCacheHashtable;

typedef struct {
    TrunkFDCacheHashtable htable;
    struct {
        int capacity;
        int count;
        struct fc_list_head head;
    } lru;
    struct fast_mblock_man allocator;
} TrunkFDCacheContext;

#ifdef __cplusplus
extern "C" {
#endif

    int trunk_fd_cache_init(TrunkFDCacheContext *cache_ctx, const int capacity);

    //return fd, -1 for not exist
    int trunk_fd_cache_get(TrunkFDCacheContext *cache_ctx,
            const uint32_t trunk_id);

    int trunk_fd_cache_add(TrunkFDCacheContext *cache_ctx,
            const uint32_t trunk_id, const int fd);

    int trunk_fd_cache_delete(TrunkFDCacheContext *cache_ctx,
            const uint32_t trunk_id);

    static inline void dio_get_trunk_filename(DATrunkSpaceInfo *space,
            char *trunk_filename, const int size)
    {
        snprintf(trunk_filename, size, "%s/%04d/%06u",
                space->store->path.str, space->id_info.subdir,
                space->id_info.id);
    }

    static inline void dio_get_space_log_filename(const uint32_t trunk_id,
            char *binlog_filename, const int size)
    {
        DATrunkFileInfo *trunk;

        if ((trunk=trunk_hashtable_get(trunk_id)) != NULL) {
            snprintf(binlog_filename, size, "%s/%04d/.%06u.log",
                    trunk->allocator->path_info->store.path.str,
                    trunk->id_info.subdir, trunk->id_info.id);
        } else {
            snprintf(binlog_filename, size, "%s/.unkown_trunk.log",
                    DA_DATA_PATH_STR);
        }
    }

#ifdef __cplusplus
}
#endif

#endif
