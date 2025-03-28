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


#ifndef _DA_TRUNK_FD_CACHE_H
#define _DA_TRUNK_FD_CACHE_H

#include "fastcommon/fc_list.h"
#include "../storage_types.h"
#include "../trunk/trunk_allocator.h"
#include "../trunk/trunk_hashtable.h"

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_fd_cache_init(DATrunkFDCacheContext *cache_ctx,
            const int capacity);

    //return fd, -1 for not exist
    int da_trunk_fd_cache_get(DATrunkFDCacheContext *cache_ctx,
            const uint64_t trunk_id);

    int da_trunk_fd_cache_add(DATrunkFDCacheContext *cache_ctx,
            const uint64_t trunk_id, const int fd);

    int da_trunk_fd_cache_delete(DATrunkFDCacheContext *cache_ctx,
            const uint64_t trunk_id);

    void da_trunk_fd_cache_clear(DATrunkFDCacheContext *cache_ctx);

    static inline void dio_get_trunk_filename(DATrunkSpaceInfo *space,
            char *trunk_filename, const int size)
    {
        snprintf(trunk_filename, size, "%s/%04u/%06"PRId64,
                space->store->path.str, space->id_info.subdir,
                space->id_info.id);
    }

    static inline void dio_get_space_log_filename(DAContext *ctx, const
            uint64_t trunk_id, char *binlog_filename, const int size)
    {
        DATrunkFileInfo *trunk;

        if ((trunk=da_trunk_hashtable_get(&ctx->trunk_htable_ctx,
                        trunk_id)) != NULL)
        {
            snprintf(binlog_filename, size, "%s/%04u/.%06"PRId64".log",
                    trunk->allocator->path_info->store.path.str,
                    trunk->id_info.subdir, trunk->id_info.id);
        } else {
            snprintf(binlog_filename, size, "%s/.unkown_trunk.log",
                    ctx->data.path.str);
        }
    }

#ifdef __cplusplus
}
#endif

#endif
