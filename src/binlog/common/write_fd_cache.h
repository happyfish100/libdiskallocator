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

#ifndef _DA_WRITE_FD_CACHE_H
#define _DA_WRITE_FD_CACHE_H

#include "binlog_fd_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

    extern DABinlogFDCacheContext g_da_write_cache_ctx;

    static inline int da_write_fd_cache_init_ex(const char *data_path,
            const char *subdir_name, const int max_idle_time,
            const int capacity, da_binlog_fd_cache_filename_func
            filename_func, const int subdirs)
    {
        const int open_flags =  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC;
        return da_binlog_fd_cache_init(&g_da_write_cache_ctx,
                data_path, subdir_name, open_flags, max_idle_time,
                capacity, filename_func, subdirs);
    }

    static inline int da_write_fd_cache_init(const char *data_path,
            const char *subdir_name, const int max_idle_time,
            const int capacity, const int subdirs)
    {
        return da_write_fd_cache_init_ex(data_path, subdir_name, max_idle_time,
                capacity, da_binlog_fd_cache_binlog_filename, subdirs);
    }

    //return fd, < 0 for error
    static inline int da_write_fd_cache_get(const uint64_t id)
    {
        return da_binlog_fd_cache_get(&g_da_write_cache_ctx, id);
    }

    static inline int da_write_fd_cache_remove(const uint64_t id)
    {
        return da_binlog_fd_cache_remove(&g_da_write_cache_ctx, id);
    }

    static inline void da_write_fd_cache_clear()
    {
        return da_binlog_fd_cache_clear(&g_da_write_cache_ctx);
    }

    static inline const char *da_write_fd_cache_filename(
            const uint64_t id, char *full_filename, const int size)
    {
        return g_da_write_cache_ctx.filename_func(&g_da_write_cache_ctx,
                id, full_filename, size);
    }

#ifdef __cplusplus
}
#endif

#endif
