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


#ifndef _DISK_ALLOCATOR_GLOBAL_H
#define _DISK_ALLOCATOR_GLOBAL_H

#include "fastcommon/common_define.h"
#include "sf/sf_global.h"
#include "storage/storage_config.h"

typedef struct disk_allocator_global_vars {
    struct {
        string_t path;   //data path
        int binlog_buffer_size;
        int binlog_subdirs;
    } data;

    struct {
        int file_block_size;
        FSStorageConfig cfg;
    } storage;

    int my_server_id;

} DiskAllocatorGlobalVars;

#define DATA_PATH             g_disk_allocator_vars.data.path
#define DATA_PATH_STR         DATA_PATH.str
#define DATA_PATH_LEN         DATA_PATH.len

#define BINLOG_BUFFER_SIZE    g_disk_allocator_vars.data.binlog_buffer_size
#define BINLOG_SUBDIRS        g_disk_allocator_vars.data.binlog_subdirs

#define MY_SERVER_ID          g_disk_allocator_vars.my_server_id
#define STORAGE_CFG           g_disk_allocator_vars.storage.cfg
#define FILE_BLOCK_SIZE       g_disk_allocator_vars.storage.file_block_size

#ifdef __cplusplus
extern "C" {
#endif

    extern DiskAllocatorGlobalVars g_disk_allocator_vars;

    /*
       //TODO
    const int my_server_id, const int file_block_size
    */

#ifdef __cplusplus
}
#endif

#endif
