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
#include "binlog/trunk/trunk_index.h"
#include "binlog/trunk/trunk_binlog.h"
#include "binlog/trunk/trunk_space_log.h"
#include "trunk/trunk_hashtable.h"
#include "trunk/trunk_prealloc.h"
#include "trunk/trunk_maker.h"
#include "storage_allocator.h"
#include "global.h"

DiskAllocatorGlobalVars g_disk_allocator_vars;

int da_global_init(const int my_server_id)
{
    int result;

    if (g_disk_allocator_vars.inited) {
        return 0;
    }

    if ((result=fast_mblock_init_ex1(&DA_TRUNK_ALLOCATOR,
                    "trunk_file_info", sizeof(DATrunkFileInfo),
                    16384, 0, NULL, NULL, true)) != 0)
    {
        return result;
    }

    DA_MY_SERVER_ID = my_server_id;
    base64_init_ex(&DA_BASE64_CTX, 0, '-', '_', '.');
    g_disk_allocator_vars.inited = true;
    return 0;
}

int da_load_config_ex(DAContext *context, const char *module_name,
        const int file_block_size, const DADataConfig *data_cfg,
        const char *storage_filename, const bool have_extra_field,
        const bool destroy_store_path_index,
        const bool migrate_path_mark_filename)
{
    int result;

    context->module_name = module_name;
    context->storage.file_block_size = file_block_size;
    context->data = *data_cfg;
    context->storage.have_extra_field = have_extra_field;
    context->storage.migrate_path_mark_filename = migrate_path_mark_filename;
    if ((result=da_storage_config_load(context, &context->storage.cfg,
                    storage_filename, destroy_store_path_index)) == 0)
    {
        da_storage_config_to_log(context, &context->storage.cfg);
    }

    return result;
}

int da_init_start_ex(DAContext *ctx, da_slice_migrate_done_callback
        slice_migrate_done_callback, da_trunk_migrate_done_callback
        trunk_migrate_done_callback, da_cached_slice_write_done_callback
        cached_slice_write_done, const int skip_path_index)
{
    int result;

    ctx->slice_migrate_done_callback = slice_migrate_done_callback;
    ctx->trunk_migrate_done_callback = trunk_migrate_done_callback;
    ctx->cached_slice_write_done = cached_slice_write_done;
    ctx->storage.skip_path_index = skip_path_index;
    da_trunk_index_init(ctx);

    if ((result=da_trunk_hashtable_init(&ctx->trunk_htable_ctx)) != 0) {
        return result;
    }

    if ((result=da_trunk_write_thread_init(ctx)) != 0) {
        return result;
    }

    if ((result=da_trunk_read_thread_init(ctx)) != 0) {
        return result;
    }

    if ((result=da_trunk_space_log_init(ctx)) != 0) {
        return result;
    }

    if ((result=da_storage_allocator_init(ctx)) != 0) {
        return result;
    }

    if ((result=da_trunk_binlog_init(ctx)) != 0) {
        return result;
    }

    if ((result=da_trunk_space_log_start(ctx)) != 0) {
        return result;
    }

    if ((result=da_trunk_maker_init(ctx)) != 0) {
        return result;
    }

    if ((result=da_storage_allocator_prealloc_trunk_freelists(ctx)) != 0) {
        return result;
    }

    if ((result=da_trunk_prealloc_init(ctx)) != 0) {
        return result;
    }

    return 0;
}
