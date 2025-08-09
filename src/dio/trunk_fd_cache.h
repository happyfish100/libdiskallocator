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
        char *p;

        if (space->store->path.len + 32 > size) {
            snprintf(trunk_filename, size, "%s/%04u/%06"PRId64,
                    space->store->path.str, space->id_info.subdir,
                    space->id_info.id);
        } else {
            memcpy(trunk_filename, space->store->path.str,
                    space->store->path.len);
            p = trunk_filename + space->store->path.len;
            *p++ = '/';
            p += fc_ltostr_ex(space->id_info.subdir, p, 4);
            *p++ = '/';
            p += fc_ltostr_ex(space->id_info.id, p, 6);
        }
    }

    static inline void dio_get_space_log_filename(DAContext *ctx, const
            uint64_t trunk_id, char *binlog_filename, const int size)
    {
#define UNKOWN_TRUNK_FILENAME_STR ".unkown_trunk.log"
#define UNKOWN_TRUNK_FILENAME_LEN (sizeof(UNKOWN_TRUNK_FILENAME_STR) - 1)
#define THE_TRUNK_PATH  trunk->allocator->path_info

        DATrunkFileInfo *trunk;
        char *p;

        if ((trunk=da_trunk_hashtable_get(&ctx->trunk_htable_ctx,
                        trunk_id)) != NULL)
        {
            if (THE_TRUNK_PATH->store.path.len + 32 > size) {
                snprintf(binlog_filename, size, "%s/%04u/.%06"PRId64".log",
                        THE_TRUNK_PATH->store.path.str,
                        trunk->id_info.subdir, trunk->id_info.id);
            } else {
                memcpy(binlog_filename, THE_TRUNK_PATH->store.path.str,
                        THE_TRUNK_PATH->store.path.len);
                p = binlog_filename + THE_TRUNK_PATH->store.path.len;
                *p++ = '/';
                p += fc_ltostr_ex(trunk->id_info.subdir, p, 4);
                *p++ = '/';
                *p++ = '.';
                p += fc_ltostr_ex(trunk->id_info.id, p, 6);
                *p++ = '.';
                *p++ = 'l';
                *p++ = 'o';
                *p++ = 'g';
                *p++ = '\0';
            }
        } else {
            fc_get_full_filename_ex(ctx->data.path.str, ctx->data.path.len,
                    UNKOWN_TRUNK_FILENAME_STR, UNKOWN_TRUNK_FILENAME_LEN,
                    binlog_filename, size);
        }
    }

#ifdef __cplusplus
}
#endif

#endif
