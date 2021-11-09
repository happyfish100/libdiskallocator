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
#include <assert.h>
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
#include "../dio/trunk_read_thread.h"
#include "../dio/trunk_write_thread.h"
#include "../binlog/trunk/trunk_space_log.h"
#include "trunk_reclaim.h"

int trunk_reclaim_init_ctx(TrunkReclaimContext *rctx)
{
    const int alloc_skiplist_once = 1;
    const bool allocator_use_lock = false;
    int result;

#ifdef OS_LINUX
    rctx->op_ctx.buffer_type = da_buffer_type_array;
    rctx->buffer_size = 0;
    rctx->op_ctx.buff = NULL;
#else
    rctx->buffer_size = 256 * 1024;
    rctx->op_ctx.buff = (char *)fc_malloc(rctx->buffer_size);
    if (rctx->op_ctx.buff == NULL) {
        return ENOMEM;
    }
#endif

    if ((result=da_space_log_reader_init(&rctx->reader,
                    alloc_skiplist_once, allocator_use_lock)) != 0)
    {
        return result;
    }

    if ((result=init_pthread_lock_cond_pair(&rctx->notifies.rw.lcp)) != 0) {
        return result;
    }
    rctx->notifies.rw.result = 0;

    if ((result=init_pthread_lock_cond_pair(&rctx->notifies.log.lcp)) != 0) {
        return result;
    }
    rctx->notifies.log.waiting_count = 0;

    return 0;
}

static int realloc_rb_array(TrunkReclaimBlockArray *array)
{
    TrunkReclaimBlockInfo *blocks;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 1024;
    bytes = sizeof(TrunkReclaimBlockInfo) * new_alloc;
    blocks = (TrunkReclaimBlockInfo *)fc_malloc(bytes);
    if (blocks == NULL) {
        return ENOMEM;
    }

    if (array->blocks != NULL) {
        if (array->count > 0) {
            memcpy(blocks, array->blocks, array->count *
                    sizeof(TrunkReclaimBlockInfo));
        }
        free(array->blocks);
    }

    array->alloc = new_alloc;
    array->blocks = blocks;
    return 0;
}

static int combine_to_rb_array(TrunkReclaimContext *rctx,
        TrunkReclaimBlockArray *barray)
{
    int result;
    UniqSkiplistIterator it;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *tail;
    TrunkReclaimBlockInfo *block;

    rctx->slice_count = 0;
    uniq_skiplist_iterator(rctx->skiplist, &it);
    block = barray->blocks;
    record = uniq_skiplist_next(&it);
    while (record != NULL) {
        if (barray->alloc <= block - barray->blocks) {
            barray->count = block - barray->blocks;
            if ((result=realloc_rb_array(barray)) != 0) {
                return result;
            }
            block = barray->blocks + barray->count;
        }
        rctx->slice_count++;

        block->total_size = record->storage.size;
        block->head = tail = record;
        while ((record=uniq_skiplist_next(&it)) != NULL &&
                (tail->storage.offset + tail->storage.size ==
                 record->storage.offset) && (block->total_size +
                     record->storage.size <= DA_FILE_BLOCK_SIZE))
        {
            block->total_size += record->storage.size;
            tail->next = record;
            tail = record;
            rctx->slice_count++;
        }

        tail->next = NULL;  //end of record chain
        block++;
    }

    barray->count = block - barray->blocks;
    return 0;
}

static int migrate_prepare(TrunkReclaimContext *rctx,
        DATrunkSpaceLogRecord *record)
{
    rctx->op_ctx.storage = &record->storage;

#ifdef OS_LINUX
#else
    if (rctx->buffer_size < record->storage.size) {
        char *buff;
        int buffer_size;

        buffer_size = rctx->buffer_size * 2;
        while (buffer_size < record->storage.size) {
            buffer_size *= 2;
        }
        buff = (char *)fc_malloc(buffer_size);
        if (buff == NULL) {
            return ENOMEM;
        }

        free(rctx->op_ctx.buff);
        rctx->op_ctx.buff = buff;
        rctx->buffer_size = buffer_size;
    }
#endif

    return 0;
}

static inline void log_rw_error(DASliceOpContext *op_ctx,
        const int result, const int ignore_errno, const char *caption)
{
    int log_level;
    log_level = (result == ignore_errno) ? LOG_DEBUG : LOG_ERR;
    log_it_ex(&g_log_context, log_level,
            "file: "__FILE__", line: %d, %s slice fail, "
            "trunk id: %u, offset: %u, length: %u, size: %u, "
            "errno: %d, error info: %s", __LINE__, caption,
            op_ctx->storage->trunk_id, op_ctx->storage->offset,
            op_ctx->storage->length, op_ctx->storage->size,
            result, STRERROR(result));
}

static int slice_write(TrunkReclaimContext *rctx,
        const uint64_t oid, DATrunkSpaceInfo *space)
{
    int count;
    int result;
    char *buff;

    count = 1;
    if ((result=storage_allocator_reclaim_alloc(oid, rctx->op_ctx.
                    storage->length, space, &count)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "alloc disk space %d bytes fail, "
                "errno: %d, error info: %s", __LINE__,
                rctx->op_ctx.storage->length,
                result, STRERROR(result));
        return result;
    }

#ifdef OS_LINUX
    buff = rctx->op_ctx.aio_buffer->buff + rctx->op_ctx.aio_buffer->offset;
#else
    buff = rctx->op_ctx.buff;
#endif

    return trunk_write_thread_by_buff_synchronize(
            space, buff, &rctx->notifies.rw);
}

static int migrate_one_slice(TrunkReclaimContext *rctx,
        DATrunkSpaceLogRecord *record)
{
    int result;
    DATrunkSpaceInfo space;

    if ((result=migrate_prepare(rctx, record)) != 0) {
        return result;
    }

    if ((result=da_slice_read(&rctx->op_ctx, &rctx->notifies.rw)) != 0) {
        log_rw_error(&rctx->op_ctx, result, ENOENT, "read");
        return result == ENOENT ? 0 : result;
    }

    if ((result=slice_write(rctx, record->oid, &space)) != 0) {
        log_rw_error(&rctx->op_ctx, result, 0, "write");
        return result;
    }

    record->storage.trunk_id = space.id_info.id;
    record->storage.offset = space.offset;
    record->storage.size = space.size;

#ifdef OS_LINUX
    read_buffer_pool_free(rctx->op_ctx.aio_buffer);
#endif

    return 0;
}

static int migrate_one_block(TrunkReclaimContext *rctx,
        TrunkReclaimBlockInfo *block)
{
    DATrunkSpaceLogRecord holder;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *old_record;
    DATrunkSpaceLogRecord *new_record;
    int result;
    uint32_t offset;
    DAPieceFieldInfo field;
    struct fc_queue_info space_chain;

    holder = *(block->head);
    holder.storage.length = holder.storage.size = block->total_size;
    if ((result=migrate_one_slice(rctx, &holder)) != 0) {
        return result;
    }

    offset = holder.storage.offset;
    record = block->head;
    while (record != NULL) {
        old_record = (DATrunkSpaceLogRecord *)fast_mblock_alloc_object(
                &rctx->reader.record_allocator);
        if (old_record == NULL) {
            return ENOMEM;
        }

        new_record = (DATrunkSpaceLogRecord *)fast_mblock_alloc_object(
                &rctx->reader.record_allocator);
        if (new_record == NULL) {
            return ENOMEM;
        }

        old_record->oid = record->oid;
        old_record->fid = record->fid;
        old_record->op_type = da_binlog_op_type_reclaim_space;
        old_record->storage = record->storage;

        new_record->oid = record->oid;
        new_record->fid = record->fid;
        new_record->op_type = da_binlog_op_type_consume_space;
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
        field.source = DA_FIELD_UPDATE_SOURCE_RECLAIM;
        field.op_type = da_binlog_op_type_update;
        field.storage = new_record->storage;
        if ((result=DA_REDO_QUEUE_PUSH_FUNC(&field, &space_chain,
                        &rctx->notifies.log)) != 0)
        {
            return result;
        }

        offset += record->storage.size;
        record = record->next;
    }

    return 0;
}

static int migrate_blocks(TrunkReclaimContext *rctx)
{
    TrunkReclaimBlockInfo *block;
    TrunkReclaimBlockInfo *bend;
    int result;

    __sync_add_and_fetch(&rctx->notifies.log.
            waiting_count, rctx->slice_count);

    bend = rctx->barray.blocks + rctx->barray.count;
    for (block=rctx->barray.blocks; block<bend; block++) {
        if ((result=migrate_one_block(rctx, block)) != 0) {
            return result;
        }
    }

    sf_synchronize_counter_wait(&rctx->notifies.log);
    return 0;
}

int trunk_reclaim(DATrunkAllocator *allocator, DATrunkFileInfo *trunk,
        TrunkReclaimContext *rctx)
{
    int result;

    if ((result=da_space_log_reader_load(&rctx->reader,
                    trunk->id_info.id, &rctx->skiplist)) != 0)
    {
        return result;
    }

    do {
        if ((result=combine_to_rb_array(rctx, &rctx->barray)) != 0) {
            break;
        }

        if ((result=migrate_blocks(rctx)) != 0) {
            break;
        }
    } while (0);

    uniq_skiplist_free(rctx->skiplist);
    return result;
}
