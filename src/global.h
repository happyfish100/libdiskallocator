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

    int da_load_config_ex(DAContext *context, const char *module_name,
            const int file_block_size, const DADataConfig *data_cfg,
            const char *storage_filename, const bool have_extra_field,
            const bool destroy_store_path_index,
            const bool migrate_path_mark_filename);

    static inline int da_load_config(DAContext *context,
            const char *module_name, const int file_block_size,
            const DADataConfig *data_cfg, const char *storage_filename)
    {
        const bool have_extra_field = false;
        const bool destroy_store_path_index = true;
        const bool migrate_path_mark_filename = false;
        return da_load_config_ex(context, module_name, file_block_size,
                data_cfg, storage_filename, have_extra_field,
                destroy_store_path_index, migrate_path_mark_filename);
    }

    int da_init_ex(DAContext *ctx, da_slice_load_done_callback
            slice_load_done_callback, da_slice_migrate_done_callback
            slice_migrate_done_callback, da_trunk_migrate_done_callback
            trunk_migrate_done_callback, da_cached_slice_write_done_callback
            cached_slice_write_done, const int skip_path_index);

    void da_destroy(DAContext *ctx);

    int da_start(DAContext *ctx);

    static inline void da_set_slice_migrate_done_callback(DAContext *ctx,
            da_slice_migrate_done_callback slice_migrate_done_callback)
    {
        ctx->slice_migrate_done_callback = slice_migrate_done_callback;
    }

#define da_init(ctx, slice_migrate_done_callback) \
    da_init_ex(ctx, NULL, slice_migrate_done_callback, NULL, NULL, -1)

#ifdef __cplusplus
}
#endif

#endif
