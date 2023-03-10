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
#include "fastcommon/base64.h"
#include "sf/sf_global.h"
#include "binlog/common/binlog_types.h"
#include "storage_config.h"

typedef struct {
    bool inited;
    int my_server_id;
    struct base64_context base64_ctx;
    struct fast_mblock_man trunk_allocator;  //element: DATrunkAllocator
    da_binlog_unpack_record_func unpack_record;
    da_binlog_shrink_func shrink;
} DiskAllocatorGlobalVars;

#define DA_MY_SERVER_ID        g_disk_allocator_vars.my_server_id
#define DA_BASE64_CTX          g_disk_allocator_vars.base64_ctx
#define DA_TRUNK_ALLOCATOR     g_disk_allocator_vars.trunk_allocator

#ifdef __cplusplus
extern "C" {
#endif

    extern DiskAllocatorGlobalVars g_disk_allocator_vars;

    int da_global_init(const int my_server_id);

    int da_load_config(DAContext *context, const int file_block_size,
            const DADataConfig *data_cfg, const char *storage_filename,
            const bool have_extra_field);

    int da_init_start_ex(DAContext *ctx, da_redo_queue_push_func
            redo_queue_push_func, da_cached_slice_write_done_callback
            cached_slice_write_done);

#define da_init_start(ctx, redo_queue_push_func) \
    da_init_start_ex(ctx, redo_queue_push_func, NULL)

#ifdef __cplusplus
}
#endif

#endif
