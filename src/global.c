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

#include "dio/trunk_read_thread.h"
#include "dio/trunk_write_thread.h"
#include "binlog/trunk/trunk_binlog.h"
#include "trunk/trunk_hashtable.h"
#include "trunk/trunk_prealloc.h"
#include "trunk/trunk_maker.h"
#include "storage_allocator.h"
#include "global.h"

DiskAllocatorGlobalVars g_disk_allocator_vars;

int da_load_config(const int my_server_id, const int file_block_size,
        const DADataGlobalConfig *data_cfg, const char *storage_filename)
{
    DA_MY_SERVER_ID = my_server_id;
    DA_FILE_BLOCK_SIZE = file_block_size;
    g_disk_allocator_vars.data = *data_cfg;
    return storage_config_load(&DA_STORE_CFG, storage_filename);
}

int da_init_start(da_redo_queue_push_func redo_queue_push_func)
{
    int result;

    DA_REDO_QUEUE_PUSH_FUNC = redo_queue_push_func;
    if ((result=trunk_hashtable_init()) != 0) {
        return result;
    }

    if ((result=trunk_write_thread_init()) != 0) {
        return result;
    }

    if ((result=trunk_read_thread_init()) != 0) {
        return result;
    }

    if ((result=storage_allocator_init()) != 0) {
        return result;
    }

    if ((result=trunk_binlog_init()) != 0) {
        return result;
    }

    if ((result=storage_allocator_prealloc_trunk_freelists()) != 0) {
        return result;
    }

    if ((result=trunk_prealloc_init()) != 0) {
        return result;
    }

    if ((result=trunk_maker_init()) != 0) {
        return result;
    }

    return 0;
}
