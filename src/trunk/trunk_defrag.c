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
#include "sf/sf_global.h"
#include "sf/sf_func.h"
#include "../global.h"
#include "../storage_allocator.h"
#include "../dio/trunk_fd_cache.h"
#include "../dio/trunk_write_thread.h"
#include "../binlog/trunk/trunk_space_log.h"
#include "trunk_defrag.h"

static inline void push_trunk_util_event_force(DATrunkAllocator *allocator,
        DATrunkFileInfo *trunk, const int event)
{
    int old_event;

    while (1) {
        old_event = __sync_add_and_fetch(&trunk->util.event, 0);
        if (event == old_event) {
            return;
        }

        if (__sync_bool_compare_and_swap(&trunk->util.event,
                    old_event, event))
        {
            if (old_event == DA_TRUNK_UTIL_EVENT_NONE) {
                fc_queue_push(&allocator->reclaim.queue, trunk);
            }
            return;
        }
    }
}

static int realloc_rb_array(DATrunkDefragBlockArray *array)
{
    DATrunkDefragBlockInfo *blocks;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 1024;
    bytes = sizeof(DATrunkDefragBlockInfo) * new_alloc;
    blocks = (DATrunkDefragBlockInfo *)fc_malloc(bytes);
    if (blocks == NULL) {
        return ENOMEM;
    }

    if (array->blocks != NULL) {
        if (array->count > 0) {
            memcpy(blocks, array->blocks, array->count *
                    sizeof(DATrunkDefragBlockInfo));
        }
        free(array->blocks);
    }

    array->alloc = new_alloc;
    array->blocks = blocks;
    return 0;
}

static int combine_records_to_rb_array(DATrunkDefragThread *thread,
        DATrunkDefragBlockArray *barray)
{
    int result;
    UniqSkiplistIterator it;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *tail;
    DATrunkDefragBlockInfo *block;

    uniq_skiplist_iterator(thread->skiplist, &it);
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
        thread->slice_counts.total++;

        block->total_length = record->storage.length;
        block->head = tail = record;
        while ((record=uniq_skiplist_next(&it)) != NULL &&
                (record->slice_type == tail->slice_type) &&
                (record->oid == tail->oid && record->fid == tail->fid &&
                 tail->extra + tail->storage.length == record->extra) &&
                (tail->storage.offset + tail->storage.length ==
                 record->storage.offset) && (block->total_length +
                     record->storage.size <= thread->ctx->da_ctx->
                     storage.file_block_size))
        {
            tail->next = record;
            tail = record;
            block->total_length += record->storage.length;
            thread->slice_counts.total++;
        }

        if (block->head != tail) {  //more than 1 slice merged
            tail->next = NULL;  //end of record chain
            block++;
        }
    }

    barray->count = block - barray->blocks;
    return 0;
}

static int migrate_merged_slice(DATrunkDefragThread *thread,
        DATrunkFileInfo *trunk, DATrunkDefragBlockInfo *block)
{
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *r;
    DAPieceFieldInfo field;
    DASliceMigrateArgument arg;
    int flags;
    int slice_count;
    int64_t max_version;
    int result;

    slice_count = 0;
    record = r = block->head;
    max_version = r->storage.version;
    do {
        if (r->storage.version > max_version) {
            max_version = r->storage.version;
        }
        ++slice_count;
    } while ((r=r->next) != NULL);

    thread->slice_counts.merged += slice_count;

    field.oid = record->oid;
    field.fid = record->fid;
    field.extra = record->extra;
    field.source = DA_FIELD_UPDATE_SOURCE_RECLAIM;
    field.op_type = da_binlog_op_type_update;
    field.storage.version = max_version;
    field.storage.trunk_id = record->storage.trunk_id;
    field.storage.offset = record->storage.offset;
    field.storage.length = block->total_length;
    field.storage.size = block->total_length;
    arg.slice_type = record->slice_type;
    if ((result=thread->ctx->da_ctx->slice_migrate_done_callback(trunk,
                    &field, &arg, &thread->log_notify, &flags)) != 0)
    {
        return result;
    }

    if (flags == DA_REDO_QUEUE_PUSH_FLAGS_SKIP) {
        thread->slice_counts.skip += slice_count;
    } else if (flags == DA_REDO_QUEUE_PUSH_FLAGS_IGNORE) {
        thread->slice_counts.ignore += slice_count;
    }
    return 0;
}

static int migrate_blocks(DATrunkDefragThread *thread, DATrunkFileInfo *trunk)
{
    DATrunkDefragBlockInfo *block;
    DATrunkDefragBlockInfo *bend;
    int result;

    __sync_add_and_fetch(&thread->log_notify.waiting_count,
            thread->barray.count);

    bend = thread->barray.blocks + thread->barray.count;
    for (block=thread->barray.blocks; block<bend; block++) {
        if ((result=migrate_merged_slice(thread, trunk, block)) != 0) {
            return result;
        }
    }

    if (thread->ctx->da_ctx->trunk_migrate_done_callback != NULL) {
        thread->ctx->da_ctx->trunk_migrate_done_callback(trunk);
    }
    sf_synchronize_counter_wait(&thread->log_notify);

    return 0;
}

static int merge_continuous_slices_do(
        DATrunkDefragThread *thread,
        DATrunkFileInfo *trunk)
{
    int result;
    int64_t time_used;
    double avg_slices;
    char time_buff[64];
    char time_prompt[64];
    int64_t start_time_us;

    start_time_us = get_current_time_us();
    thread->slice_counts.total = 0;
    thread->slice_counts.merged = 0;
    thread->slice_counts.skip = 0;
    thread->slice_counts.ignore = 0;
    if ((result=da_space_log_reader_load(&thread->reader, trunk->
                    id_info.id, &thread->skiplist)) != 0)
    {
        thread->barray.count = 0;
        return result;
    }

    if (!uniq_skiplist_empty(thread->skiplist)) {
        if ((result=combine_records_to_rb_array(thread, &thread->barray)) == 0) {
            if (thread->barray.count > 0) {
                result = migrate_blocks(thread, trunk);
            }
        }
    }
    uniq_skiplist_free(thread->skiplist);

    if (thread->barray.count > 0) {
        avg_slices = (double)thread->slice_counts.merged /
            (double)thread->barray.count;
    } else {
        avg_slices = 0.00;
    }

    time_used = (get_current_time_us() - start_time_us) / 1000;
    long_to_comma_str(time_used, time_buff);
    sprintf(time_prompt, "time used: %s ms", time_buff);
    logInfo("file: "__FILE__", line: %d, %s "
            "path index: %d, defrag trunk id: %"PRId64", total slice count: "
            "%d, merged stat {block count: %d, slice count {total: %d, "
            "skip: %d, ignore: %d}, arg slices per block: %.2f}, %s",
            __LINE__, trunk->allocator->path_info->ctx->module_name,
            trunk->allocator->path_info->store.index, trunk->id_info.id,
            thread->slice_counts.total, thread->barray.count,
            thread->slice_counts.merged, thread->slice_counts.skip,
            thread->slice_counts.ignore, avg_slices, time_prompt);

    return result;
}

static int init_thread(DATrunkDefragThread *thread)
{
    const int alloc_skiplist_once = 1;
    const bool allocator_use_lock = false;
    int offset;
    int result;

    if ((result=da_space_log_reader_init(&thread->reader, thread->ctx->da_ctx,
                    alloc_skiplist_once, allocator_use_lock)) != 0)
    {
        return result;
    }

    if ((result=sf_synchronize_ctx_init(&thread->log_notify)) != 0) {
        return result;
    }

    offset = (unsigned long)(&((DATrunkFileInfo *)NULL)->
            merge_continuous_slices.next);
    if ((result=fc_queue_init(&thread->queue, offset)) != 0) {
        return result;
    }

    return 0;
}

static inline void deal_defrag_requests(DATrunkDefragThread *thread,
        DATrunkFileInfo *head)
{
    DATrunkFileInfo *trunk;

    while (head != NULL && SF_G_CONTINUE_FLAG) {
        trunk = head;
        head = head->merge_continuous_slices.next;

        merge_continuous_slices_do(thread, trunk);
        push_trunk_util_event_force(trunk->allocator,
                trunk, DA_TRUNK_UTIL_EVENT_CREATE);
        da_set_trunk_status(trunk, DA_TRUNK_STATUS_NONE);
    }
}

static void *trunk_defrag_thread_func(void *arg)
{
    DATrunkDefragThread *thread;
    DATrunkFileInfo *head;

    thread = (DATrunkDefragThread *)arg;

#ifdef OS_LINUX
    {
        char thread_name[16];
        snprintf(thread_name, sizeof(thread_name),
                "trunk-defrag[%d]", thread->index);
        prctl(PR_SET_NAME, thread_name);
    }
#endif

    FC_ATOMIC_INC(thread->ctx->running_count);
    while (SF_G_CONTINUE_FLAG) {
        head = (DATrunkFileInfo *)fc_queue_pop_all(&thread->queue);
        if (head == NULL) {
            continue;
        }

        deal_defrag_requests(thread, head);
    }

    FC_ATOMIC_DEC(thread->ctx->running_count);
    return NULL;
}

int da_trunk_defrag_init(DAContext *ctx)
{
    int result;
    int bytes;
    pthread_t tid;
    DATrunkDefragThread *thread;
    DATrunkDefragThread *end;

    if (!ctx->storage.cfg.merge_continuous_slices.enabled) {
        ctx->trunk_defrag_ctx = NULL;
        return 0;
    }

    bytes = sizeof(DATrunkDefragContext) + sizeof(DATrunkDefragThread) *
        ctx->storage.cfg.merge_continuous_slices.threads;
    ctx->trunk_defrag_ctx = fc_malloc(bytes);
    if (ctx->trunk_defrag_ctx == NULL) {
        return ENOMEM;
    }
    memset(ctx->trunk_defrag_ctx, 0, bytes);

    ctx->trunk_defrag_ctx->da_ctx = ctx;
    ctx->trunk_defrag_ctx->thread_array.threads = (DATrunkDefragThread *)
        (ctx->trunk_defrag_ctx + 1);
    end = ctx->trunk_defrag_ctx->thread_array.threads + ctx->storage.
        cfg.merge_continuous_slices.threads;
    for (thread=ctx->trunk_defrag_ctx->thread_array.threads;
            thread<end; thread++)
    {
        thread->ctx = ctx->trunk_defrag_ctx;
        thread->index = thread - ctx->trunk_defrag_ctx->thread_array.threads;
        if ((result=init_thread(thread)) != 0) {
            return result;
        }

        if ((result=fc_create_thread(&tid, trunk_defrag_thread_func,
                        thread, SF_G_THREAD_STACK_SIZE)) != 0)
        {
            return result;
        }
    }
    ctx->trunk_defrag_ctx->thread_array.count = ctx->storage.
        cfg.merge_continuous_slices.threads;

    return 0;
}

void da_trunk_defrag_check_push(DATrunkFileInfo *trunk)
{
    DAContext *ctx;
    DATrunkDefragThread *thread;

    ctx = trunk->allocator->path_info->ctx;
    da_set_trunk_status(trunk, DA_TRUNK_STATUS_REPUSH);
    if (ctx->storage.cfg.merge_continuous_slices.enabled) {
        thread = ctx->trunk_defrag_ctx->thread_array.threads +
            trunk->id_info.id % ctx->trunk_defrag_ctx->thread_array.count;
        fc_queue_push(&thread->queue, trunk);
    } else {
        push_trunk_util_event_force(trunk->allocator,
                trunk, DA_TRUNK_UTIL_EVENT_CREATE);
        da_set_trunk_status(trunk, DA_TRUNK_STATUS_NONE);
    }
}
