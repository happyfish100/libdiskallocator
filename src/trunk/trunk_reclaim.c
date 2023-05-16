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

#include <limits.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fc_queue.h"
#include "fastcommon/common_blocked_queue.h"
#include "sf/sf_global.h"
#include "sf/sf_func.h"
#include "../global.h"
#include "../storage_allocator.h"
#include "../dio/trunk_fd_cache.h"
#include "../dio/trunk_write_thread.h"
#include "../binlog/trunk/trunk_space_log.h"
#include "trunk_reclaim.h"

int da_trunk_reclaim_init_ctx(DATrunkReclaimContext *rctx, DAContext *ctx)
{
    const int alloc_skiplist_once = 1;
    const bool allocator_use_lock = false;
    int result;

    rctx->ctx = ctx;
    if ((result=da_space_log_reader_init(&rctx->reader, ctx,
                    alloc_skiplist_once, allocator_use_lock)) != 0)
    {
        return result;
    }

    if ((result=da_init_read_context(&rctx->read_ctx)) != 0) {
        return result;
    }

    if ((result=sf_synchronize_ctx_init(&rctx->log_notify)) != 0) {
        return result;
    }

    return 0;
}

static int realloc_rb_array(DATrunkReclaimBlockArray *array)
{
    DATrunkReclaimBlockInfo *blocks;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 1024;
    bytes = sizeof(DATrunkReclaimBlockInfo) * new_alloc;
    blocks = (DATrunkReclaimBlockInfo *)fc_malloc(bytes);
    if (blocks == NULL) {
        return ENOMEM;
    }

    if (array->blocks != NULL) {
        if (array->count > 0) {
            memcpy(blocks, array->blocks, array->count *
                    sizeof(DATrunkReclaimBlockInfo));
        }
        free(array->blocks);
    }

    array->alloc = new_alloc;
    array->blocks = blocks;
    return 0;
}

static int realloc_space_array(DATrunkReclaimSpaceAllocArray *array)
{
    DATrunkReclaimSpaceAllocInfo *spaces;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 64;
    bytes = sizeof(DATrunkReclaimSpaceAllocInfo) * new_alloc;
    spaces = (DATrunkReclaimSpaceAllocInfo *)fc_malloc(bytes);
    if (spaces == NULL) {
        return ENOMEM;
    }

    if (array->spaces != NULL) {
        if (array->count > 0) {
            memcpy(spaces, array->spaces, array->count *
                    sizeof(DATrunkReclaimSpaceAllocInfo));
        }
        free(array->spaces);
    }

    array->alloc = new_alloc;
    array->spaces = spaces;
    return 0;
}

static int combine_to_rb_array(DATrunkReclaimContext *rctx,
        DATrunkReclaimBlockArray *barray)
{
    int result;
    DASliceType slice_type;
    UniqSkiplistIterator it;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *tail;
    DATrunkReclaimBlockInfo *block;

    uniq_skiplist_iterator(rctx->skiplist, &it);
    block = barray->blocks;
    record = uniq_skiplist_next(&it);
    while (record != NULL) {
        while (record->slice_type == DA_SLICE_TYPE_CACHE) {
            if ((record=uniq_skiplist_next(&it)) == NULL) {
                barray->count = block - barray->blocks;
                return 0;
            }
        }

        if (barray->alloc <= block - barray->blocks) {
            barray->count = block - barray->blocks;
            if ((result=realloc_rb_array(barray)) != 0) {
                return result;
            }
            block = barray->blocks + barray->count;
        }
        rctx->slice_counts.total++;

        slice_type = record->slice_type;
        block->total_size = record->storage.size;
        block->head = tail = record;
        while ((record=uniq_skiplist_next(&it)) != NULL &&
                record->slice_type == slice_type && (tail->storage.offset +
                 tail->storage.size == record->storage.offset) &&
                (block->total_size + record->storage.size <=
                 rctx->ctx->storage.file_block_size))
        {
            block->total_size += record->storage.size;
            tail->next = record;
            tail = record;
            rctx->slice_counts.total++;
        }

        tail->next = NULL;  //end of record chain
        block++;
    }

    barray->count = block - barray->blocks;
    return 0;
}

static inline void log_rw_error(DAContext *ctx, DASliceOpContext *op_ctx,
        const int result, const int ignore_errno, const char *caption)
{
    int log_level;
    log_level = (result == ignore_errno) ? LOG_DEBUG : LOG_ERR;
    log_it_ex(&g_log_context, log_level,
            "file: "__FILE__", line: %d, %s %s slice fail, "
            "trunk id: %"PRId64", offset: %u, length: %u, size: %u, "
            "errno: %d, error info: %s", __LINE__, ctx->module_name,
            caption, op_ctx->storage->trunk_id, op_ctx->storage->offset,
            op_ctx->storage->length, op_ctx->storage->size,
            result, STRERROR(result));
}

static int migrate_one_slice(DATrunkReclaimContext *rctx,
        DATrunkSpaceLogRecord *record, DATrunkFileInfo **trunk)
{
    int result;
    int count;
    DATrunkSpaceWithVersion space_info;

    count = 1;
    if ((result=da_storage_allocator_reclaim_alloc(rctx->ctx,
                    record->oid, record->storage.length,
                    &space_info, &count)) != 0)
    {
        logError("file: "__FILE__", line: %d, %s "
                "alloc disk space %d bytes fail, errno: %d, "
                "error info: %s", __LINE__, rctx->ctx->module_name,
                record->storage.length, result, STRERROR(result));
        return result;
    }

    if (record->slice_type == DA_SLICE_TYPE_FILE) {
        rctx->read_ctx.op_ctx.storage = &record->storage;
        if ((result=da_slice_read(rctx->ctx, &rctx->read_ctx)) != 0) {
            log_rw_error(rctx->ctx, &rctx->read_ctx.op_ctx,
                    result, ENOENT, "read");
            return result == ENOENT ? 0 : result;
        }

        if ((result=da_trunk_write_thread_by_buff_synchronize(rctx->ctx,
                        &space_info, DA_OP_CTX_BUFFER_PTR(rctx->read_ctx.
                            op_ctx), &rctx->read_ctx.sctx)) != 0)
        {
            log_rw_error(rctx->ctx, &rctx->read_ctx.op_ctx,
                    result, 0, "write");
            return result;
        }

        rctx->migrage_bytes += record->storage.length;
    }

    *trunk = space_info.ts.trunk;
    if (rctx->sarray.count == 0 || rctx->sarray.spaces[rctx->
            sarray.count - 1].trunk != *trunk)
    {
        if (rctx->sarray.alloc <= rctx->sarray.count) {
            if ((result=realloc_space_array(&rctx->sarray)) != 0) {
                return result;
            }
        }

        rctx->sarray.spaces[rctx->sarray.count].trunk = *trunk;
        rctx->sarray.spaces[rctx->sarray.count].alloc_count = 1;
        rctx->sarray.count++;
    } else {
        rctx->sarray.spaces[rctx->sarray.count - 1].alloc_count++;
    }

    record->storage.trunk_id = space_info.ts.space.id_info.id;
    record->storage.offset = space_info.ts.space.offset;
    record->storage.size = space_info.ts.space.size;
    return 0;
}

static int migrate_one_block(DATrunkReclaimContext *rctx,
        DATrunkReclaimBlockInfo *block)
{
    DATrunkSpaceLogRecord holder;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *old_record;
    DATrunkSpaceLogRecord *new_record;
    int result;
    int flags;
    uint32_t offset;
    DATrunkFileInfo *trunk = NULL;
    DAPieceFieldInfo field;
    struct fc_queue_info space_chain;

    holder = *(block->head);
    holder.storage.length = holder.storage.size = block->total_size;
    if ((result=migrate_one_slice(rctx, &holder, &trunk)) != 0) {
        return result;
    }

    offset = holder.storage.offset;
    record = block->head;
    while (record != NULL) {
        old_record = da_trunk_space_log_alloc_record(rctx->ctx);
        if (old_record == NULL) {
            return ENOMEM;
        }

        new_record = da_trunk_space_log_alloc_record(rctx->ctx);
        if (new_record == NULL) {
            return ENOMEM;
        }

        old_record->oid = record->oid;
        old_record->fid = record->fid;
        old_record->extra = record->extra;
        old_record->op_type = da_binlog_op_type_reclaim_space;
        old_record->slice_type = record->slice_type;
        old_record->storage = record->storage;

        new_record->oid = record->oid;
        new_record->fid = record->fid;
        new_record->extra = record->extra;
        new_record->op_type = da_binlog_op_type_consume_space;
        new_record->slice_type = record->slice_type;
        new_record->storage.version = record->storage.version;
        new_record->storage.trunk_id = holder.storage.trunk_id;
        new_record->storage.offset = offset;
        new_record->storage.length = record->storage.length;
        new_record->storage.size = record->storage.size;

        old_record->next = new_record;
        new_record->next = NULL;
        space_chain.head = old_record;
        space_chain.tail = new_record;

        field.oid = record->oid;
        field.fid = record->fid;
        field.extra = record->extra;
        field.source = DA_FIELD_UPDATE_SOURCE_RECLAIM;
        field.op_type = da_binlog_op_type_update;
        field.storage = new_record->storage;
        if ((result=rctx->ctx->slice_migrate_done_callback(trunk, &field,
                        &space_chain, &rctx->log_notify, &flags)) != 0)
        {
            return result;
        }

        if (flags == DA_REDO_QUEUE_PUSH_FLAGS_SKIP) {
            rctx->slice_counts.skip++;
        } else if (flags == DA_REDO_QUEUE_PUSH_FLAGS_IGNORE) {
            rctx->slice_counts.ignore++;
        }

        offset += record->storage.size;
        record = record->next;
    }

    return 0;
}

static int migrate_blocks(DATrunkReclaimContext *rctx, DATrunkFileInfo *trunk)
{
    DATrunkReclaimBlockInfo *block;
    DATrunkReclaimBlockInfo *bend;
    DATrunkReclaimSpaceAllocInfo *space;
    DATrunkReclaimSpaceAllocInfo *send;
    int result;

    if (rctx->barray.count == 0) {
        return 0;
    }

    __sync_add_and_fetch(&rctx->log_notify.waiting_count,
            rctx->slice_counts.total);

    rctx->sarray.count = 0;
    bend = rctx->barray.blocks + rctx->barray.count;
    for (block=rctx->barray.blocks; block<bend; block++) {
        if ((result=migrate_one_block(rctx, block)) != 0) {
            return result;
        }
    }

    if (rctx->ctx->trunk_migrate_done_callback != NULL) {
        rctx->ctx->trunk_migrate_done_callback(trunk);
    }
    sf_synchronize_counter_wait(&rctx->log_notify);

    if (rctx->sarray.count == 1) {  //fast path
        da_trunk_freelist_decrease_writing_count_ex(rctx->sarray.spaces[0].
                trunk, rctx->sarray.spaces[0].alloc_count);
    } else {
        send = rctx->sarray.spaces + rctx->sarray.count;
        for (space=rctx->sarray.spaces; space<send; space++) {
            da_trunk_freelist_decrease_writing_count_ex(
                    space->trunk, space->alloc_count);
        }
    }

    return 0;
}

int da_trunk_reclaim(DATrunkReclaimContext *rctx, DATrunkAllocator
        *allocator, DATrunkFileInfo *trunk)
{
    int result;

    rctx->migrage_bytes = 0;
    rctx->slice_counts.total = 0;
    rctx->slice_counts.skip = 0;
    rctx->slice_counts.ignore = 0;
    if ((result=da_space_log_reader_load(&rctx->reader, trunk->
                    id_info.id, &rctx->skiplist)) != 0)
    {
        rctx->barray.count = 0;
        return result;
    }

    if (!uniq_skiplist_empty(rctx->skiplist)) {
        if ((result=combine_to_rb_array(rctx, &rctx->barray)) == 0) {
            result = migrate_blocks(rctx, trunk);
        }
    }

    uniq_skiplist_free(rctx->skiplist);
    return result;
}
