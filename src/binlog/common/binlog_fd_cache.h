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

struct da_binlog_fd_cache_context;
typedef const char *(*da_binlog_fd_cache_filename_func)(
        struct da_binlog_fd_cache_context *cache_ctx,
        const uint64_t id, char *full_filename, const int size);

typedef struct da_binlog_fd_cache_context {
    char *data_path;
    char subdir_name[64];
    DABinlogFDCacheHashtable htable;
    int open_flags;
    int max_idle_time;
    short subdirs;
    short subdir_mask;
    short subdir_bits;
    struct {
        int capacity;
        int count;
        struct fc_list_head head;
    } lru;
    struct fast_mblock_man allocator;
    da_binlog_fd_cache_filename_func filename_func;
} DABinlogFDCacheContext;


#ifdef __cplusplus
extern "C" {
#endif

    int da_binlog_fd_cache_init(DABinlogFDCacheContext *cache_ctx,
            const char *data_path, const char *subdir_name,
            const int open_flags, const int max_idle_time,
            const int capacity, da_binlog_fd_cache_filename_func
            filename_func, const int subdirs);

    //return fd, < 0 for error
    int da_binlog_fd_cache_get(DABinlogFDCacheContext *cache_ctx,
            const uint64_t id);

    int da_binlog_fd_cache_remove(DABinlogFDCacheContext *cache_ctx,
            const uint64_t id);

    void da_binlog_fd_cache_clear(DABinlogFDCacheContext *cache_ctx);

    static inline const char *da_binlog_fd_cache_binlog_filename_ex(
            const char *data_path, const char *subdir_name,
            const uint32_t subdirs, const uint64_t id,
            char *full_filename, const int size)
    {
#define BINLOG_FILENAME_PREFIX_STR  "binlog."
#define BINLOG_FILENAME_PREFIX_LEN  (sizeof(BINLOG_FILENAME_PREFIX_STR) - 1)

        int path_index;
        int path_len;
        int subdir_len;
        char *p;

        path_index = id % subdirs;
        path_len = strlen(data_path);
        subdir_len = strlen(subdir_name);
        if (path_len + subdir_len + 32 > size) {
            snprintf(full_filename, size, "%s/%s/%02X/%02X/%s%08"PRIX64,
                    data_path, subdir_name, path_index, path_index,
                    BINLOG_FILENAME_PREFIX_STR, id);
        } else {
            p = full_filename;
            memcpy(p, data_path, path_len);
            p += path_len;
            *p++ = '/';
            memcpy(p, subdir_name, subdir_len);
            p += subdir_len;
            *p++ = '/';
            *p++ = g_upper_hex_chars[(path_index >> 4) & 0x0F];
            *p++ = g_upper_hex_chars[path_index & 0x0F];
            *p++ = '/';
            *p++ = g_upper_hex_chars[(path_index >> 4) & 0x0F];
            *p++ = g_upper_hex_chars[path_index & 0x0F];
            *p++ = '/';
            memcpy(p, BINLOG_FILENAME_PREFIX_STR, BINLOG_FILENAME_PREFIX_LEN);
            p += BINLOG_FILENAME_PREFIX_LEN;
            if (id <= UINT32_MAX) {
                int2HEX(id, p, 8);
            } else {
                long2HEX(id, p, 8);
            }
        }

        return full_filename;
    }

    static inline const char *da_binlog_fd_cache_hash_filename_ex(
            const char *data_path, const char *subdir_name,
            const int subdir_bits, const int subdir_mask,
            const uint64_t id, char *full_filename, const int size)
    {
        int subdir1;
        int subdir2;
        int file_id;
        int path_len;
        int subdir_len;
        char *p;

        subdir1 = ((id >> (2 * subdir_bits)) & subdir_mask);
        subdir2 = ((id >> subdir_bits) & subdir_mask);
        file_id = (id & subdir_mask);
        path_len = strlen(data_path);
        subdir_len = strlen(subdir_name);
        if (path_len + subdir_len + 32 > size) {
            snprintf(full_filename, size, "%s/%s/%02X/%02X/%02X",
                    data_path, subdir_name, subdir1, subdir2, file_id);
        } else {
            p = full_filename;
            memcpy(p, data_path, path_len);
            p += path_len;
            *p++ = '/';
            memcpy(p, subdir_name, subdir_len);
            p += subdir_len;
            *p++ = '/';
            *p++ = g_upper_hex_chars[(subdir1 >> 4) & 0x0F];
            *p++ = g_upper_hex_chars[subdir1 & 0x0F];
            *p++ = '/';
            *p++ = g_upper_hex_chars[(subdir2 >> 4) & 0x0F];
            *p++ = g_upper_hex_chars[subdir2 & 0x0F];
            *p++ = '/';
            if (file_id <= UINT8_MAX) {
                *p++ = g_upper_hex_chars[(file_id >> 4) & 0x0F];
                *p++ = g_upper_hex_chars[file_id & 0x0F];
                *p++ = '\0';
            } else if (file_id <= UINT16_MAX) {
                short2HEX(file_id, p, 2);
            } else {
                int2HEX(file_id, p, 2);
            }
        }

        return full_filename;
    }

    const char *da_binlog_fd_cache_binlog_filename(
            DABinlogFDCacheContext *cache_ctx, const uint64_t id,
            char *full_filename, const int size);

    const char *da_binlog_fd_cache_hash_filename(
            DABinlogFDCacheContext *cache_ctx, const uint64_t id,
            char *full_filename, const int size);

#ifdef __cplusplus
}
#endif

#endif
