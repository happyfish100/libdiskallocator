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

    if (ctx->storage.merge_continuous_slices.value) {
        if ((result=fc_check_realloc_iovec_array(&rctx->
                        iovec_array, IOV_MAX)) != 0)
        {
            return result;
        }
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

static int realloc_storage_array(DATrunkReclaimStorageArray *array)
{
    DAPieceFieldStorage *storages;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 1024;
    bytes = sizeof(DAPieceFieldStorage) * new_alloc;
    storages = (DAPieceFieldStorage *)fc_malloc(bytes);
    if (storages == NULL) {
        return ENOMEM;
    }

    if (array->storages != NULL) {
        if (array->count > 0) {
            memcpy(storages, array->storages, array->count *
                    sizeof(DAPieceFieldStorage));
        }
        free(array->storages);
    }

    array->alloc = new_alloc;
    array->storages = storages;
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

static int realloc_rs_array(DATrunkReclaimSliceArray *array)
{
    DATrunkSpaceLogRecord **records;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 1024;
    bytes = sizeof(DATrunkSpaceLogRecord *) * new_alloc;
    records = (DATrunkSpaceLogRecord **)fc_malloc(bytes);
    if (records == NULL) {
        return ENOMEM;
    }

    if (array->records != NULL) {
        if (array->count > 0) {
            memcpy(records, array->records, array->count *
                    sizeof(DATrunkSpaceLogRecord *));
        }
        free(array->records);
    }

    array->alloc = new_alloc;
    array->records = records;
    return 0;
}

static int compare_by_block_slice_key(const DATrunkSpaceLogRecord **r1,
        const DATrunkSpaceLogRecord **r2)
{
    int sub;
    if ((sub=fc_compare_int64((*r1)->oid, (*r2)->oid)) != 0) {
        return sub;
    }

    if ((sub=fc_compare_int64((*r1)->fid, (*r2)->fid)) != 0) {
        return sub;
    }

    return (*r1)->extra - (*r2)->extra;
}

static int convert_to_rs_array(DATrunkReclaimContext *rctx,
        DATrunkReclaimSliceArray *rs_array)
{
    int result;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord **dest;
    UniqSkiplistIterator it;

    dest = rs_array->records;
    uniq_skiplist_iterator(rctx->skiplist, &it);
    while ((record=uniq_skiplist_next(&it)) != NULL) {
        if (record->slice_type == DA_SLICE_TYPE_CACHE) {
            continue;
        }

        if (rs_array->alloc <= dest - rs_array->records) {
            rs_array->count = dest - rs_array->records;
            if ((result=realloc_rs_array(rs_array)) != 0) {
                return result;
            }
            dest = rs_array->records + rs_array->count;
        }

        *dest++ = record;
    }

    rs_array->count = dest - rs_array->records;
    if (rs_array->count > 1) {
        qsort(rs_array->records, rs_array->count,
                sizeof(DATrunkSpaceLogRecord *),
                (int (*)(const void *, const void *))
                compare_by_block_slice_key);
    }

    rctx->slice_counts.total = rs_array->count;
    return 0;
}

static int combine_slices_to_rb_array(DATrunkReclaimSliceArray *sarray,
        DATrunkReclaimBlockArray *barray)
{
    int result;
    DATrunkSpaceLogRecord **record;
    DATrunkSpaceLogRecord **send;
    DATrunkSpaceLogRecord *tail;
    DATrunkReclaimBlockInfo *block;

    barray->count = 0;
    if (barray->alloc < sarray->count) {
        if ((result=realloc_rb_array(barray)) != 0) {
            return result;
        }
    }

    send = sarray->records + sarray->count;
    record = sarray->records;
    block = barray->blocks;
    while (record < send) {
        block->head = tail = *record;
        block->total_length = (*record)->storage.length;
        record++;

        while (record < send && (*record)->slice_type == tail->slice_type &&
                ((*record)->oid == tail->oid && (*record)->fid == tail->fid) &&
                (tail->extra + tail->storage.length == (*record)->extra))
        {  //combine slices
            block->total_length += (*record)->storage.length;
            tail->next = *record;
            tail = *record;
            record++;
        }
        tail->next = NULL;  //end of record chain
        block++;
    }

    barray->count = block - barray->blocks;
    return 0;
}

static int combine_records_to_storage_array(DATrunkReclaimContext *rctx,
        DATrunkReclaimStorageArray *storage_array)
{
    int result;
    DASliceType slice_type;
    UniqSkiplistIterator it;
    DATrunkSpaceLogRecord *record;
    DAPieceFieldStorage *storage;

    uniq_skiplist_iterator(rctx->skiplist, &it);
    storage = storage_array->storages;
    record = uniq_skiplist_next(&it);
    while (record != NULL) {
        while (record->slice_type != DA_SLICE_TYPE_FILE) {
            if ((record=uniq_skiplist_next(&it)) == NULL) {
                storage_array->count = storage - storage_array->storages;
                return 0;
            }
        }

        if (storage_array->alloc <= storage - storage_array->storages) {
            storage_array->count = storage - storage_array->storages;
            if ((result=realloc_storage_array(storage_array)) != 0) {
                return result;
            }
            storage = storage_array->storages + storage_array->count;
        }

        slice_type = record->slice_type;
        *storage = record->storage;
        while ((record=uniq_skiplist_next(&it)) != NULL &&
                record->slice_type == slice_type && (storage->offset +
                    storage->size == record->storage.offset) &&
                (storage->size + record->storage.size <=
                 rctx->ctx->storage.file_block_size))
        {
            storage->size += record->storage.size;
        }
        storage->length = storage->size;

        storage++;
    }

    storage_array->count = storage - storage_array->storages;
    return 0;
}

static int combine_records_to_rb_array(DATrunkReclaimContext *rctx,
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

static int read_by_storage_array(DATrunkReclaimContext *rctx,
        DATrunkReclaimStorageArray *storage_array,
        const uint32_t trunk_size)
{
    DAPieceFieldStorage *storage;
    DAPieceFieldStorage *end;
    char *new_buff;
    BufferInfo buffer;
    int result;

    if (rctx->trunk_content.alloc_size < trunk_size) {
        if ((new_buff=fc_malloc(trunk_size)) == NULL) {
            return ENOMEM;
        }
        if (rctx->trunk_content.buff != NULL) {
            free(rctx->trunk_content.buff);
        }
        rctx->trunk_content.buff = new_buff;
        rctx->trunk_content.alloc_size = trunk_size;
    }

    end = storage_array->storages + storage_array->count;
    for (storage=storage_array->storages; storage<end; storage++) {
        buffer.buff = rctx->trunk_content.buff + storage->offset;
        buffer.alloc_size = rctx->trunk_content.alloc_size - storage->offset;
        rctx->read_ctx.op_ctx.storage = storage;
        if ((result=da_slice_read_ex(rctx->ctx, &rctx->
                        read_ctx, &buffer)) != 0)
        {
            log_rw_error(rctx->ctx, &rctx->read_ctx.op_ctx,
                    result, ENOENT, "read");
            return result == ENOENT ? 0 : result;
        }
    }

    return 0;
}

static int write_one_slice(DATrunkReclaimContext *rctx,
        DATrunkReclaimBlockInfo *block, DATrunkSpaceLogRecord *record,
        DATrunkSpaceWithVersion *space_info)
{
    int result;
    struct iovec *iov;
    DATrunkSpaceLogRecord *r;

    rctx->read_ctx.op_ctx.storage = &record->storage;
    if (rctx->ctx->storage.merge_continuous_slices.value) {
        if (block->head->next == NULL) {  //only merged one slice
            if ((result=da_trunk_write_thread_by_buff_synchronize(rctx->
                            ctx, space_info, rctx->trunk_content.
                            buff + block->head->storage.offset,
                            &rctx->read_ctx.sctx)) != 0)
            {
                log_rw_error(rctx->ctx, &rctx->read_ctx.op_ctx,
                        result, 0, "write");
            }
        } else {
            iov = rctx->iovec_array.iovs;
            r = block->head;
            do {
                if (rctx->iovec_array.alloc <= iov - rctx->iovec_array.iovs) {
                    rctx->iovec_array.count = iov - rctx->iovec_array.iovs;
                    if ((result=fc_check_realloc_iovec_array(&rctx->
                                    iovec_array, rctx->iovec_array.
                                    count + 1)) != 0)
                    {
                        return result;
                    }
                    iov = rctx->iovec_array.iovs + rctx->iovec_array.count;
                }

                iov->iov_base = rctx->trunk_content.buff + r->storage.offset;
                iov->iov_len = r->storage.length;
                iov++;
            } while ((r=r->next) != NULL);

            rctx->iovec_array.count = iov - rctx->iovec_array.iovs;
            if ((result=da_trunk_write_thread_by_iovec_synchronize(
                            rctx->ctx, space_info, &rctx->iovec_array,
                            &rctx->read_ctx.sctx)) != 0)
            {
                log_rw_error(rctx->ctx, &rctx->read_ctx.op_ctx,
                        result, 0, "write");
            }
        }
    } else {
        if ((result=da_slice_read(rctx->ctx, &rctx->read_ctx)) != 0) {
            log_rw_error(rctx->ctx, &rctx->read_ctx.op_ctx,
                    result, ENOENT, "read");
            return result == ENOENT ? 0 : result;
        }

        if ((result=da_trunk_write_thread_by_buff_synchronize(rctx->ctx,
                        space_info, DA_OP_CTX_BUFFER_PTR(rctx->read_ctx.
                            op_ctx), &rctx->read_ctx.sctx)) != 0)
        {
            log_rw_error(rctx->ctx, &rctx->read_ctx.op_ctx,
                    result, 0, "write");
        }
    }

    return result;
}

static int migrate_one_slice(DATrunkReclaimContext *rctx,
        DATrunkReclaimBlockInfo *block, DATrunkSpaceLogRecord *record,
        DATrunkFileInfo **trunk)
{
    int result;
    int count;
    DATrunkSpaceWithVersion space_info;

    count = 1;
    if ((result=da_storage_allocator_reclaim_alloc(rctx->ctx,
                    record->oid, record->storage.length,
                    &space_info, &count, record->slice_type)) != 0)
    {
        logError("file: "__FILE__", line: %d, %s "
                "alloc disk space %d bytes fail, errno: %d, "
                "error info: %s", __LINE__, rctx->ctx->module_name,
                record->storage.length, result, STRERROR(result));
        return result;
    }

    if (record->slice_type == DA_SLICE_TYPE_FILE) {
        if ((result=write_one_slice(rctx, block, record, &space_info)) != 0) {
            return result;
        }
        rctx->migrage_bytes += record->storage.length;
    }

    *trunk = space_info.ts.trunk;
    if (rctx->space_array.count == 0 || rctx->space_array.spaces[
            rctx->space_array.count - 1].trunk != *trunk)
    {
        if (rctx->space_array.alloc <= rctx->space_array.count) {
            if ((result=realloc_space_array(&rctx->space_array)) != 0) {
                return result;
            }
        }

        rctx->space_array.spaces[rctx->space_array.count].trunk = *trunk;
        rctx->space_array.spaces[rctx->space_array.count].alloc_count = 1;
        rctx->space_array.count++;
    } else {
        rctx->space_array.spaces[rctx->space_array.count - 1].alloc_count++;
    }

    record->storage.trunk_id = space_info.ts.space.id_info.id;
    record->storage.offset = space_info.ts.space.offset;
    record->storage.size = space_info.ts.space.size;
    return 0;
}

static int migrate_merged_slice(DATrunkReclaimContext *rctx,
        DATrunkReclaimBlockInfo *block)
{
    DATrunkSpaceLogRecord holder;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *old_record;
    DATrunkSpaceLogRecord *new_record;
    DATrunkFileInfo *trunk = NULL;
    DAPieceFieldInfo field;
    struct fc_queue_info space_chain;
    int flags;
    int slice_count;
    int64_t max_version;
    int result;

    holder = *(block->head);
    holder.storage.length = holder.storage.size = block->total_length;
    if ((result=migrate_one_slice(rctx, block, &holder, &trunk)) != 0) {
        return result;
    }

    slice_count = 0;
    space_chain.head = space_chain.tail = NULL;
    record = block->head;
    max_version = record->storage.version;
    do {
        if (record->storage.version > max_version) {
            max_version = record->storage.version;
        }

        old_record = da_trunk_space_log_alloc_record(rctx->ctx);
        if (old_record == NULL) {
            return ENOMEM;
        }
        old_record->oid = record->oid;
        old_record->fid = record->fid;
        old_record->extra = record->extra;
        old_record->slice_type = record->slice_type;
        old_record->storage = record->storage;
        old_record->op_type = da_binlog_op_type_reclaim_space;

        if (space_chain.head == NULL) {
            space_chain.head = old_record;
        } else {
            ((DATrunkSpaceLogRecord *)space_chain.tail)->next = old_record;
        }
        space_chain.tail = old_record;
        ++slice_count;
    } while ((record=record->next) != NULL);

    new_record = da_trunk_space_log_alloc_record(rctx->ctx);
    if (new_record == NULL) {
        return ENOMEM;
    }
    new_record->oid = holder.oid;
    new_record->fid = holder.fid;
    new_record->extra = holder.extra;
    new_record->slice_type = holder.slice_type;
    new_record->storage.version = max_version;
    new_record->storage.trunk_id = holder.storage.trunk_id;
    new_record->storage.offset = holder.storage.offset;
    new_record->storage.length = holder.storage.length;
    new_record->storage.size = holder.storage.size;
    new_record->op_type = da_binlog_op_type_consume_space;

    ((DATrunkSpaceLogRecord *)space_chain.tail)->next = new_record;
    new_record->next = NULL;
    space_chain.tail = new_record;

    field.oid = new_record->oid;
    field.fid = new_record->fid;
    field.extra = new_record->extra;
    field.source = DA_FIELD_UPDATE_SOURCE_RECLAIM;
    field.op_type = da_binlog_op_type_update;
    field.storage = new_record->storage;
    if ((result=rctx->ctx->slice_migrate_done_callback(trunk, &field,
                    &space_chain, &rctx->log_notify, &flags)) != 0)
    {
        return result;
    }

    if (flags == DA_REDO_QUEUE_PUSH_FLAGS_SKIP) {
        rctx->slice_counts.skip += slice_count;
    } else if (flags == DA_REDO_QUEUE_PUSH_FLAGS_IGNORE) {
        rctx->slice_counts.ignore += slice_count;
    }
    return 0;
}

static int migrate_one_block(DATrunkReclaimContext *rctx,
        DATrunkReclaimBlockInfo *block)
{
    DATrunkSpaceLogRecord holder;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *old_record;
    DATrunkSpaceLogRecord *new_record;
    DATrunkFileInfo *trunk = NULL;
    DAPieceFieldInfo field;
    struct fc_queue_info space_chain;
    uint32_t offset;
    int flags;
    int result;

    holder = *(block->head);
    holder.storage.length = holder.storage.size = block->total_size;
    if ((result=migrate_one_slice(rctx, block, &holder, &trunk)) != 0) {
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
        old_record->slice_type = record->slice_type;
        old_record->storage = record->storage;
        old_record->op_type = da_binlog_op_type_reclaim_space;

        new_record->oid = record->oid;
        new_record->fid = record->fid;
        new_record->extra = record->extra;
        new_record->slice_type = record->slice_type;
        new_record->storage.version = record->storage.version;
        new_record->storage.trunk_id = holder.storage.trunk_id;
        new_record->storage.offset = offset;
        new_record->storage.length = record->storage.length;
        new_record->storage.size = record->storage.size;
        new_record->op_type = da_binlog_op_type_consume_space;

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

    if (rctx->ctx->storage.merge_continuous_slices.value) {
        if ((result=read_by_storage_array(rctx, &rctx->
                        storage_array, trunk->size)) != 0)
        {
            return result;
        }

        __sync_add_and_fetch(&rctx->log_notify.waiting_count,
                rctx->barray.count);
    } else {
        __sync_add_and_fetch(&rctx->log_notify.waiting_count,
                rctx->slice_counts.total);
    }

    rctx->space_array.count = 0;
    bend = rctx->barray.blocks + rctx->barray.count;
    for (block=rctx->barray.blocks; block<bend; block++) {
        if (rctx->ctx->storage.merge_continuous_slices.value) {
            if ((result=migrate_merged_slice(rctx, block)) != 0) {
                return result;
            }
        } else {
            if ((result=migrate_one_block(rctx, block)) != 0) {
                return result;
            }
        }
    }

    if (rctx->ctx->trunk_migrate_done_callback != NULL) {
        rctx->ctx->trunk_migrate_done_callback(trunk);
    }
    sf_synchronize_counter_wait(&rctx->log_notify);

    if (rctx->space_array.count == 1) {  //fast path
        da_trunk_freelist_decrease_writing_count_ex(rctx->space_array.
                spaces[0].trunk, rctx->space_array.spaces[0].alloc_count);
    } else {
        send = rctx->space_array.spaces + rctx->space_array.count;
        for (space=rctx->space_array.spaces; space<send; space++) {
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
        if (rctx->ctx->storage.merge_continuous_slices.value) {
            if ((result=convert_to_rs_array(rctx, &rctx->sarray)) == 0) {
                if ((result=combine_slices_to_rb_array(&rctx->
                                sarray, &rctx->barray)) == 0)
                {
                    result = combine_records_to_storage_array(
                            rctx, &rctx->storage_array);
                }
            }
        } else {
            result = combine_records_to_rb_array(rctx, &rctx->barray);
        }

        if (result == 0) {
            result = migrate_blocks(rctx, trunk);
        }
    }

    uniq_skiplist_free(rctx->skiplist);
    return result;
}
