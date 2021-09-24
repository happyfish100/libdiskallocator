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

typedef struct da_binlog_type_subdir_pair {
    int type;
    char subdir_name[64];
    da_binlog_pack_record_func pack_record;
    da_binlog_unpack_record_func unpack_record;
    da_binlog_batch_update_func batch_update;
    da_binlog_shrink_func shrink;
} DABinlogTypeSubdirPair;

typedef struct da_binlog_type_subdir_array {
    DABinlogTypeSubdirPair *pairs;
    int count;
} DABinlogTypeSubdirArray;

typedef struct da_binlog_id_fd_pair {
    DABinlogIdTypePair key;
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
    DABinlogFDCacheHashtable htable;
    DABinlogTypeSubdirArray type_subdir_array;
    int open_flags;
    int max_idle_time;
    struct {
        int capacity;
        int count;
        struct fc_list_head head;
    } lru;
    struct fast_mblock_man allocator;
} DABinlogFDCacheContext;


#define DA_BINLOG_SET_TYPE_SUBDIR_PAIR(pair, _type, _subdir_name, \
        _pack_record, _unpack_record, _batch_update, _shrink) \
        do {  \
            (pair).type = _type;  \
            snprintf((pair).subdir_name, \
                    sizeof((pair).subdir_name), \
                    "%s", _subdir_name);  \
            (pair).pack_record = _pack_record;  \
            (pair).unpack_record = _unpack_record; \
            (pair).batch_update = _batch_update;   \
            (pair).shrink = _shrink;  \
        } while (0)


#ifdef __cplusplus
extern "C" {
#endif

    int da_binlog_fd_cache_init(DABinlogFDCacheContext *cache_ctx,
            const DABinlogTypeSubdirArray *type_subdir_array,
            const int open_flags, const int max_idle_time,
            const int capacity);

    //return fd, < 0 for error
    int da_binlog_fd_cache_get(DABinlogFDCacheContext *cache_ctx,
            const DABinlogIdTypePair *key);

    int da_binlog_fd_cache_remove(DABinlogFDCacheContext *cache_ctx,
            const DABinlogIdTypePair *key);

    static inline int da_binlog_fd_cache_filename(DABinlogFDCacheContext
            *cache_ctx, const DABinlogIdTypePair *key,
            char *full_filename, const int size)
    {
        int path_index;

        path_index = key->id % DA_BINLOG_SUBDIRS;
        snprintf(full_filename, size, "%s/%s/%02X/%02X/binlog.%08"PRIX64,
                DA_DATA_PATH_STR, cache_ctx->type_subdir_array.pairs
                [key->type].subdir_name, path_index, path_index, key->id);
        return 0;
    }

#ifdef __cplusplus
}
#endif

#endif
