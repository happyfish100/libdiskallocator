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
#include "binlog/common/binlog_types.h"
#include "storage_config.h"

typedef struct {
    string_t path;   //data path
    int binlog_buffer_size;
    int binlog_subdirs;
    int trunk_index_dump_interval;
    TimeInfo trunk_index_dump_base_time;
    bool read_by_direct_io;  //if read by direct IO in Linux
} DADataGlobalConfig;

typedef struct {
    DADataGlobalConfig data;

    struct {
        int file_block_size;
        DAStorageConfig cfg;
    } storage;

    int my_server_id;

    da_redo_queue_push_func redo_queue_push_func;
} DiskAllocatorGlobalVars;

#define DA_DATA_PATH           g_disk_allocator_vars.data.path
#define DA_DATA_PATH_STR       DA_DATA_PATH.str
#define DA_DATA_PATH_LEN       DA_DATA_PATH.len

#define DA_BINLOG_BUFFER_SIZE  g_disk_allocator_vars.data.binlog_buffer_size
#define DA_BINLOG_SUBDIRS      g_disk_allocator_vars.data.binlog_subdirs

#define DA_TRUNK_INDEX_DUMP_INTERVAL  g_disk_allocator_vars. \
    data.trunk_index_dump_interval

#define DA_TRUNK_INDEX_DUMP_BASE_TIME g_disk_allocator_vars. \
    data.trunk_index_dump_base_time

#define DA_READ_BY_DIRECT_IO  g_disk_allocator_vars.data.read_by_direct_io

#define DA_MY_SERVER_ID        g_disk_allocator_vars.my_server_id
#define DA_STORE_CFG           g_disk_allocator_vars.storage.cfg
#define DA_FILE_BLOCK_SIZE     g_disk_allocator_vars.storage.file_block_size

#define DA_REDO_QUEUE_PUSH_FUNC g_disk_allocator_vars.redo_queue_push_func

#ifdef __cplusplus
extern "C" {
#endif

    extern DiskAllocatorGlobalVars g_disk_allocator_vars;

    int da_load_config(const int my_server_id, const int file_block_size,
            const DADataGlobalConfig *data_cfg, const char *storage_filename);

    int da_init_start(da_redo_queue_push_func redo_queue_push_func);

#ifdef __cplusplus
}
#endif

#endif
