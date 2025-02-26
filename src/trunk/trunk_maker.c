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
#include "../dio/trunk_write_thread.h"
#include "../binlog/trunk/trunk_space_log.h"
#include "../storage_allocator.h"
#include "trunk_reclaim.h"
#include "trunk_maker.h"

struct da_trunk_maker_thread_info;
typedef struct da_trunk_maker_task {
    bool urgent;
    DATrunkAllocator *allocator;
    struct {
        da_trunk_allocate_done_callback callback;
        void *arg;
    } notify;
    struct da_trunk_maker_thread_info *thread;
    struct da_trunk_maker_task *next;
} TrunkMakerTask;

typedef struct da_trunk_maker_thread_info {
    int index;
    SFSynchronizeContext notify;  //for notify
    DATrunkReclaimContext reclaim_ctx;
    struct fast_mblock_man task_allocator;
    struct fc_queue queue;
    pthread_t tid;
    bool running;
} TrunkMakerThreadInfo;

typedef struct da_trunk_maker_thread_array {
    int count;
    TrunkMakerThreadInfo *threads;
} TrunkMakerThreadArray;

typedef struct da_trunk_maker_context {
    volatile int running_count;
    TrunkMakerThreadArray thread_array;
} TrunkMakerContext;

static int deal_trunk_util_change_event(DATrunkAllocator *allocator,
        DATrunkFileInfo *trunk)
{
    UniqSkiplistNode *node;
    UniqSkiplistNode *prev;
    UniqSkiplistNode *previous;
    int64_t last_used_bytes;
    int status;
    int event;
    int result;

    event = __sync_add_and_fetch(&trunk->util.event, 0);
    while (1) {
        status = __sync_add_and_fetch(&trunk->status, 0);
        if (status == DA_TRUNK_STATUS_NONE) {  //accept
            break;
        } else if (status == DA_TRUNK_STATUS_REPUSH) {
            fc_queue_push(&allocator->reclaim.queue, trunk); //repush
            return EAGAIN;
        }

        if (__sync_bool_compare_and_swap(&trunk->util.event,
                    event, DA_TRUNK_UTIL_EVENT_NONE))
        {
            return EAGAIN;  //refuse
        }
        event = __sync_add_and_fetch(&trunk->util.event, 0);
    }

    switch (event) {
        case DA_TRUNK_UTIL_EVENT_CREATE:
            trunk->util.last_used_bytes = __sync_fetch_and_add(
                    &trunk->used.bytes, 0);
            result = uniq_skiplist_insert(allocator->trunks.
                    by_size.skiplist, trunk);
            break;
        case DA_TRUNK_UTIL_EVENT_UPDATE:
            if ((node=uniq_skiplist_find_node_ex(allocator->trunks.
                            by_size.skiplist, trunk, &prev)) == NULL)
            {
                result = ENOENT;
                break;
            }

            result = 0;
            previous = UNIQ_SKIPLIST_LEVEL0_PREV_NODE(node);
            if (previous != allocator->trunks.by_size.skiplist->top) {
                last_used_bytes = __sync_fetch_and_add(&trunk->used.bytes, 0);
                if (da_compare_trunk_by_size_id((DATrunkFileInfo *)
                            previous->data, last_used_bytes,
                            trunk->id_info.id) > 0)
                {
                    uniq_skiplist_delete_node(allocator->trunks.
                            by_size.skiplist, prev, node);
                    trunk->util.last_used_bytes = last_used_bytes;
                    result = uniq_skiplist_insert(allocator->trunks.
                            by_size.skiplist, trunk);
                }
            }
            break;
        default:
            result = 0;
            break;
    }

    /*
    logInfo("%s event: %c, id: %"PRId64", status: %d, last_used_bytes: "
            "%u, current used: %u, result: %d", allocator->path_info->
            ctx->module_name, event, trunk->id_info.id, trunk->status,
            trunk->util.last_used_bytes, trunk->used.bytes, result);
            */

    __sync_bool_compare_and_swap(&trunk->util.event,
            event, DA_TRUNK_UTIL_EVENT_NONE);
    return result;
}

static void deal_trunk_util_change_events(DATrunkAllocator *allocator)
{
    DATrunkFileInfo *trunk;
    DATrunkFileInfo *current;

    trunk = (DATrunkFileInfo *)fc_queue_try_pop_all(&allocator->reclaim.queue);
    while (trunk != NULL && SF_G_CONTINUE_FLAG) {
        current = trunk;
        trunk = trunk->util.next;

        deal_trunk_util_change_event(allocator, current);
    }
}

static void create_trunk_done(struct da_trunk_write_io_buffer *record,
        const int result)
{
    TrunkMakerThreadInfo *thread;

    thread = record->notify.arg1;
    PTHREAD_MUTEX_LOCK(&thread->notify.lcp.lock);
    thread->notify.finished = true;
    thread->notify.result = result >= 0 ? result : -1 * result;
    pthread_cond_signal(&thread->notify.lcp.cond);
    PTHREAD_MUTEX_UNLOCK(&thread->notify.lcp.lock);
}

static int prealloc_trunk_finish(DATrunkAllocator *allocator,
        DATrunkSpaceInfo *space, DATrunkFreelistType *freelist_type)
{
    int result;
    time_t last_stat_time;
    DATrunkFileInfo *trunk_info;

    result = da_storage_allocator_add_trunk_ex(allocator->path_info->ctx,
            space->store->index, &space->id_info, space->size, &trunk_info);
    if (result == 0) {
        *freelist_type = da_trunk_allocator_add_to_freelist(allocator, trunk_info);
    }

    __sync_add_and_fetch(&allocator->path_info->
            trunk_stat.total, space->size);

    //trigger avail space stat
    last_stat_time = __sync_add_and_fetch(&allocator->path_info->
            space_stat.last_stat_time, 0);
    __sync_bool_compare_and_swap(&allocator->path_info->space_stat.
            last_stat_time, last_stat_time, 0);
    return result;
}

static int do_prealloc_trunk(TrunkMakerThreadInfo *thread,
        TrunkMakerTask *task, DATrunkFreelistType *freelist_type)
{
    int result;
    DATrunkSpaceInfo space;

    space.store = &task->allocator->path_info->store;
    if ((result=da_trunk_id_info_generate(task->allocator->path_info->ctx,
                    space.store->index, &space.id_info)) != 0)
    {
        return result;
    }
    space.offset = 0;
    space.size = task->allocator->path_info->
        ctx->storage.cfg.trunk_file_size;
    if ((result=da_trunk_write_thread_push_trunk_op(task->allocator->
                    path_info->ctx, DA_IO_TYPE_CREATE_TRUNK,
                    &space, create_trunk_done, thread)) == 0)
    {
        PTHREAD_MUTEX_LOCK(&thread->notify.lcp.lock);
        while (!thread->notify.finished && SF_G_CONTINUE_FLAG) {
            pthread_cond_wait(&thread->notify.lcp.cond,
                    &thread->notify.lcp.lock);
        }
        if (thread->notify.finished) {
            result = thread->notify.result;
            thread->notify.finished = false;  /* reset for next */
        } else {
            result = EINTR;
        }
        PTHREAD_MUTEX_UNLOCK(&thread->notify.lcp.lock);
    }

    if (result != 0) {
        return result;
    }

    return prealloc_trunk_finish(task->allocator, &space, freelist_type);
}

static int do_reclaim_trunk(TrunkMakerThreadInfo *thread,
        TrunkMakerTask *task, DATrunkFreelistType *freelist_type)
{
    double ratio_thredhold;
    DATrunkFileInfo *trunk;
    int64_t used_bytes;
    int64_t current_bytes;
    int64_t time_used;
    char last_bytes_buff[32];
    char current_bytes_buff[32];
    char migrage_bytes_buff[32];
    char time_buff[64];
    char time_prompt[64];
    int used_count;
    int result;

    if (task->urgent || g_current_time - task->allocator->
            reclaim.last_deal_time > 10)
    {
        task->allocator->reclaim.last_deal_time = g_current_time;
        deal_trunk_util_change_events(task->allocator);
    }

    if ((trunk=(DATrunkFileInfo *)uniq_skiplist_get_first(task->
                    allocator->trunks.by_size.skiplist)) == NULL)
    {
        return ENOENT;
    }

    used_bytes = FC_ATOMIC_GET(trunk->used.bytes);
    if (used_bytes < 0) {
        used_bytes = 0;
    }
    if ((int64_t)trunk->size - used_bytes < task->allocator->
            path_info->ctx->storage.file_block_size)
    {
        return ENOENT;
    }

    ratio_thredhold = da_trunk_allocator_calc_reclaim_ratio_thredhold(
            task->allocator);

    /*
    logInfo("file: "__FILE__", line: %d, "
            "path index: %d, trunk id: %"PRId64", "
            "usage ratio: %.2f%%, ratio_thredhold: %.2f%%",
            __LINE__, task->allocator->path_info->store.index,
            trunk->id_info.id, 100.00 * (double)used_bytes /
            (double)trunk->size, 100.00 * ratio_thredhold);
            */

    if ((double)used_bytes / (double)trunk->size >= ratio_thredhold) {
        return ENOENT;
    }
    used_count = trunk->used.count;

    if (used_bytes > 0) {
        int64_t start_time_us;
        start_time_us = get_current_time_us();
        da_set_trunk_status(trunk, DA_TRUNK_STATUS_RECLAIMING);
        result = da_trunk_reclaim(&thread->reclaim_ctx,
                task->allocator, trunk);
        time_used = (get_current_time_us() - start_time_us) / 1000;
    } else {
        time_used = 0;
        result = 0;
    }

    current_bytes = FC_ATOMIC_GET(trunk->used.bytes);
    /*
    if (current_bytes < 0) {
        current_bytes = 0;
    }
    */
    long_to_comma_str(used_bytes, last_bytes_buff);
    long_to_comma_str(current_bytes, current_bytes_buff);
    long_to_comma_str(thread->reclaim_ctx.migrage_bytes, migrage_bytes_buff);
    long_to_comma_str(time_used, time_buff);
    sprintf(time_prompt, "time used: %s ms", time_buff);
    logInfo("file: "__FILE__", line: %d, %s "
            "path index: %d, reclaimed trunk id: %"PRId64", "
            "migrate block count: %d, migrage bytes: %s, "
            "slice counts {total: %d, skip: %d, ignore: %d}, "
            "trunk used count {last: %d, current: %d}, "
            "trunk used bytes {last: %s, current: %s}, "
            "last usage ratio: %.2f%%, result: %d, %s", __LINE__,
            task->allocator->path_info->ctx->module_name,
            task->allocator->path_info->store.index, trunk->id_info.id,
            thread->reclaim_ctx.barray.count, migrage_bytes_buff,
            thread->reclaim_ctx.slice_counts.total,
            thread->reclaim_ctx.slice_counts.skip,
            thread->reclaim_ctx.slice_counts.ignore,
            used_count, trunk->used.count,
            last_bytes_buff, current_bytes_buff,
            100.00 * (double)used_bytes / (double)trunk->size,
            result, time_prompt);

    if (result == 0) {
        da_trunk_space_log_push_unlink_binlog(task->allocator->path_info->
                ctx, trunk, da_trunk_space_log_current_version(
                    task->allocator->path_info->ctx), &thread->notify);

        PTHREAD_MUTEX_LOCK(&thread->notify.lcp.lock);
        while (!thread->notify.finished && SF_G_CONTINUE_FLAG) {
            pthread_cond_wait(&thread->notify.lcp.cond,
                    &thread->notify.lcp.lock);
        }
        if (thread->notify.finished) {
            result = thread->notify.result;
            thread->notify.finished = false;  /* reset for next */
        } else {
            result = EINTR;
        }
        PTHREAD_MUTEX_UNLOCK(&thread->notify.lcp.lock);

        if (result == 0) {
            PTHREAD_MUTEX_LOCK(&task->allocator->freelist.lcp.lock);
            trunk->free_start = 0;
            PTHREAD_MUTEX_UNLOCK(&task->allocator->freelist.lcp.lock);

            uniq_skiplist_delete(task->allocator->
                    trunks.by_size.skiplist, trunk);
            *freelist_type = da_trunk_allocator_add_to_freelist(
                    task->allocator, trunk);
        }
    } else {
        da_set_trunk_status(trunk, DA_TRUNK_STATUS_NONE); //rollback status
    }

    return result;
}

static int do_allocate_trunk(TrunkMakerThreadInfo *thread, TrunkMakerTask *task,
        DATrunkFreelistType *freelist_type, bool *is_new_trunk)
{
    int result;
    bool avail_enough;
    bool need_reclaim;

    *freelist_type = da_freelist_type_none;
    *is_new_trunk = false;
    if ((result=da_storage_config_calc_path_avail_space(task->
                    allocator->path_info)) != 0)
    {
        return result;
    }

    avail_enough = task->allocator->path_info->space_stat.avail -
        task->allocator->path_info->ctx->storage.cfg.trunk_file_size >
        task->allocator->path_info->reserved_space.value;
    if (task->allocator->path_info->space_stat.used_ratio <=
            task->allocator->path_info->ctx->storage.
            cfg.reclaim_trunks_on_path_usage)
    {
        need_reclaim = !avail_enough;
    } else {
        need_reclaim = true;
    }

    if (need_reclaim) {
        if ((result=do_reclaim_trunk(thread, task, freelist_type)) == 0) {
            return 0;
        }
    }

    if (avail_enough) {
        *is_new_trunk = true;
        return do_prealloc_trunk(thread, task, freelist_type);
    } else {
        return ENOSPC;
    }
}

static void deal_allocate_task(TrunkMakerThreadInfo *thread,
        TrunkMakerTask *task)
{
    int result;
    bool is_new_trunk;
    DATrunkFreelistType freelist_type;

    do {
        result = do_allocate_trunk(thread, task,
                &freelist_type, &is_new_trunk);
        if (task->notify.callback != NULL) {
            task->notify.callback(task->allocator, result,
                    is_new_trunk, task->notify.arg);
            break;
        }
    } while (result == 0 && freelist_type == da_freelist_type_reclaim);

    da_trunk_allocator_after_make_trunk(task->allocator, result);
    fast_mblock_free_object(&thread->task_allocator, task);
}

static inline void deal_allocate_requests(TrunkMakerThreadInfo *thread,
        TrunkMakerTask *head)
{
    TrunkMakerTask *task;

    while (head != NULL && SF_G_CONTINUE_FLAG) {
        task = head;
        head = head->next;

        deal_allocate_task(thread, task);
    }
}

static void *da_trunk_maker_thread_func(void *arg)
{
    TrunkMakerThreadInfo *thread;
    TrunkMakerTask *head;

    thread = (TrunkMakerThreadInfo *)arg;
    thread->running = true;

#ifdef OS_LINUX
    {
        char thread_name[16];
        snprintf(thread_name, sizeof(thread_name),
                "trunk-maker[%d]", thread->index);
        prctl(PR_SET_NAME, thread_name);
    }
#endif

    if (thread->reclaim_ctx.ctx->slice_load_done_callback != NULL) {
        while (SF_G_CONTINUE_FLAG && !thread->reclaim_ctx.
                ctx->slice_load_done_callback())
        {
            fc_sleep_ms(10);
        }
    }

    while (SF_G_CONTINUE_FLAG) {
        head = (TrunkMakerTask *)fc_queue_pop_all(&thread->queue);
        if (head == NULL) {
            continue;
        }

        deal_allocate_requests(thread, head);
    }

    thread->running = false;
    return NULL;
}

static int maker_task_alloc_init(void *element, void *args)
{
    ((TrunkMakerTask *)element)->thread = (TrunkMakerThreadInfo *)args;
    return 0;
}

int da_trunk_maker_init(DAContext *ctx)
{
    int result;
    int count;
    int bytes;
    TrunkMakerThreadInfo *thread;
    TrunkMakerThreadInfo *end;

    count = ctx->storage.cfg.trunk_prealloc_threads;
    bytes = sizeof(TrunkMakerContext) + sizeof(TrunkMakerThreadInfo) * count;
    ctx->trunk_maker_ctx = fc_malloc(bytes);
    if (ctx->trunk_maker_ctx == NULL) {
        return ENOMEM;
    }
    memset(ctx->trunk_maker_ctx, 0, bytes);
    ctx->trunk_maker_ctx->thread_array.count = count;
    ctx->trunk_maker_ctx->thread_array.threads = (TrunkMakerThreadInfo *)
        (ctx->trunk_maker_ctx + 1);

    end = ctx->trunk_maker_ctx->thread_array.threads +
        ctx->trunk_maker_ctx->thread_array.count;
    for (thread=ctx->trunk_maker_ctx->thread_array.threads;
            thread<end; thread++)
    {
        thread->index = thread - ctx->trunk_maker_ctx->thread_array.threads;
        if ((result=sf_synchronize_ctx_init(&thread->notify)) != 0) {
            return result;
        }

        if ((result=fast_mblock_init_ex1(&thread->task_allocator,
                        "maker_task", sizeof(TrunkMakerTask), 1024, 0,
                        maker_task_alloc_init, thread, true)) != 0)
        {
            return result;
        }
        if ((result=fc_queue_init(&thread->queue, (long)
                        (&((TrunkMakerTask *)NULL)->next))) != 0)
        {
            return result;
        }

        if ((result=da_trunk_reclaim_init_ctx(&thread->
                        reclaim_ctx, ctx)) != 0)
        {
            return result;
        }
    }

    return 0;
}

int da_trunk_maker_start(DAContext *ctx)
{
    int result;
    TrunkMakerThreadInfo *thread;
    TrunkMakerThreadInfo *end;

    end = ctx->trunk_maker_ctx->thread_array.threads +
        ctx->trunk_maker_ctx->thread_array.count;
    for (thread=ctx->trunk_maker_ctx->thread_array.threads;
            thread<end; thread++)
    {
        if ((result=fc_create_thread(&thread->tid, da_trunk_maker_thread_func,
                        thread, SF_G_THREAD_STACK_SIZE)) != 0)
        {
            return result;
        }
    }

    return 0;
}

int da_trunk_maker_allocate_ex(DATrunkAllocator *allocator, const bool urgent,
        const bool need_lock, da_trunk_allocate_done_callback callback, void *arg)
{
    TrunkMakerThreadInfo *thread;
    TrunkMakerTask *task;

    thread = allocator->path_info->ctx->trunk_maker_ctx->thread_array.threads +
        allocator->path_info->store.index % allocator->path_info->
        ctx->trunk_maker_ctx->thread_array.count;
    if ((task=(TrunkMakerTask *)fast_mblock_alloc_object(
                    &thread->task_allocator)) == NULL)
    {
        return ENOMEM;
    }

    task->urgent = urgent;
    task->allocator = allocator;
    task->notify.callback = callback;
    task->notify.arg = arg;
    da_trunk_allocator_before_make_trunk(allocator, need_lock);
    fc_queue_push(&thread->queue, task);
    return 0;
}
