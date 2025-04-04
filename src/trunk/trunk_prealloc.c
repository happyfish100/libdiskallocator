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
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/fc_queue.h"
#include "fastcommon/thread_pool.h"
#include "sf/sf_global.h"
#include "../global.h"
#include "../storage_allocator.h"
#include "trunk_maker.h"
#include "trunk_prealloc.h"

typedef struct trunk_preallocator_info {
    DATrunkAllocator *allocator;
    struct {
        int total;
        volatile int create;  //new create trunk count
        volatile int success;
        volatile int dealings;
    } stat;
    struct trunk_preallocator_info *next;
} TrunkPreallocatorInfo;

typedef struct trunk_preallocator_array {
    TrunkPreallocatorInfo *preallocators;
    int count;
} TrunkPreallocatorArray;

typedef struct trunk_prealloc_task {
    TrunkPreallocatorInfo *preallocator;
    struct trunk_prealloc_task *next;
} TrunkPreallocTask;

typedef struct trunk_prealloc_thread_arg {
    int result;
    bool is_new_trunk;
    pthread_lock_cond_pair_t lcp; //for allocate done notify
    struct da_trunk_prealloc_context *prealloc_ctx;
} TrunkPreallocThreadArg;

typedef struct da_trunk_prealloc_context {
    TrunkPreallocatorArray preallocator_array;
    pthread_lock_cond_pair_t lcp; //for task alloc notify
    struct fast_mblock_man task_allocator;
    struct fc_queue queue;
    FCThreadPool thread_pool;
    TrunkPreallocThreadArg *thread_args;
    time_t prealloc_end_time;
    bool in_progress;
    volatile bool finished;
    DAContext *ctx;
} DATrunkPreallocContext;

static void allocate_done_callback(DATrunkAllocator *allocator,
        const int result, const bool is_new_trunk, void *arg)
{
    TrunkPreallocThreadArg *thread_arg;

    thread_arg = (TrunkPreallocThreadArg *)arg;
    PTHREAD_MUTEX_LOCK(&thread_arg->lcp.lock);
    thread_arg->result = result >= 0 ? result : -1 * result;
    thread_arg->is_new_trunk = is_new_trunk;
    pthread_cond_signal(&thread_arg->lcp.cond);
    PTHREAD_MUTEX_UNLOCK(&thread_arg->lcp.lock);
}

static void prealloc_thread_pool_run(void *arg, void *thread_data)
{
    TrunkPreallocThreadArg *thread_arg;
    TrunkPreallocTask *task;
    int result;

    thread_arg = (TrunkPreallocThreadArg *)arg;
    while (!thread_arg->prealloc_ctx->finished) {
        task = fc_queue_try_pop(&thread_arg->prealloc_ctx->queue);
        if (task == NULL) {
            sleep(1);
            continue;
        }

        /*
        logInfo("%s prealloc task: %p, store path: %s", task->preallocator->
                allocator->path_info->ctx->module_name, task, task->
                preallocator->allocator->path_info->store.path.str);
                */

        thread_arg->is_new_trunk = false;
        if ((result=da_trunk_maker_allocate_ex(task->preallocator->allocator,
                        false, true, allocate_done_callback, thread_arg)) == 0)
        {
            PTHREAD_MUTEX_LOCK(&thread_arg->lcp.lock);
            while (thread_arg->result == -1 && SF_G_CONTINUE_FLAG) {
                pthread_cond_wait(&thread_arg->lcp.cond,
                        &thread_arg->lcp.lock);
            }

            if (thread_arg->result >= 0) {
                result = thread_arg->result;
                thread_arg->result = -1;
            } else {
                result = EINTR;
            }
            PTHREAD_MUTEX_UNLOCK(&thread_arg->lcp.lock);
        }

        /*
        logInfo("%s task: %p, store path: %s, prealloc result: %d", task->
                preallocator->allocator->path_info->ctx->module_name, task,
                task->preallocator->allocator->path_info->store.path.str,
                result);
                */

        if (thread_arg->is_new_trunk) {
            __sync_add_and_fetch(&task->preallocator->stat.create, 1);
        }

        if (result == 0) {
            __sync_add_and_fetch(&task->preallocator->stat.success, 1);
            __sync_sub_and_fetch(&task->preallocator->stat.dealings, 1);
        }

        fast_mblock_free_object(&thread_arg->prealloc_ctx->task_allocator, task);
        PTHREAD_MUTEX_LOCK(&thread_arg->prealloc_ctx->lcp.lock);
        pthread_cond_signal(&thread_arg->prealloc_ctx->lcp.cond);
        PTHREAD_MUTEX_UNLOCK(&thread_arg->prealloc_ctx->lcp.lock);
    }
}

static int init_preallocator_array(DAContext *ctx,
        TrunkPreallocatorArray *preallocator_array)
{
    int bytes;
    DATrunkAllocator **pp;
    DATrunkAllocator **end;
    TrunkPreallocatorInfo *preallocator;

    bytes = sizeof(TrunkPreallocatorInfo) * ctx->
        store_allocator_mgr->allocator_ptr_array.count;
    preallocator_array->preallocators = fc_malloc(bytes);
    if (preallocator_array->preallocators == NULL) {
        return ENOMEM;
    }
    memset(preallocator_array->preallocators, 0, bytes);

    preallocator = preallocator_array->preallocators;
    end = ctx->store_allocator_mgr->allocator_ptr_array.allocators +
        ctx->store_allocator_mgr->allocator_ptr_array.count;
    for (pp=ctx->store_allocator_mgr->allocator_ptr_array.
            allocators; pp<end; pp++)
    {
        if (*pp != NULL) {
            preallocator->allocator = *pp;
            preallocator++;
        }
    }

    preallocator_array->count = preallocator -
        preallocator_array->preallocators;

    /*
    logInfo("%s preallocator_array->count: %d", ctx->module_name,
            preallocator_array->count);
            */
    return 0;
}

static TrunkPreallocatorInfo *make_preallocator_chain(
        TrunkPreallocatorArray *preallocator_array, int *count)
{
    TrunkPreallocatorInfo *p;
    TrunkPreallocatorInfo *end;
    TrunkPreallocatorInfo *head;
    TrunkPreallocatorInfo *previous;

    *count = 0;
    head = previous = NULL;
    end = preallocator_array->preallocators + preallocator_array->count;
    for (p=preallocator_array->preallocators; p<end; p++) {
        if (da_trunk_allocator_get_freelist_count(p->allocator) <
                p->allocator->path_info->prealloc_trunks.count)
        {
            p->stat.total = 0;
            p->stat.success = 0;
            p->stat.create = 0;
            p->stat.dealings = 0;

            (*count)++;
            if (previous == NULL) {
                head = p;
            } else {
                previous->next = p;
            }
            previous = p;
        }
    }

    if (previous != NULL) {
        previous->next = NULL;
    }
    return head;
}

static void log_and_reset_preallocators(DAContext *ctx,
        TrunkPreallocatorArray *preallocator_array)
{
    TrunkPreallocatorInfo *p;
    TrunkPreallocatorInfo *end;

    end = preallocator_array->preallocators + preallocator_array->count;
    for (p=preallocator_array->preallocators; p<end; p++) {
        if (p->stat.total > 0) {
            logInfo("file: "__FILE__", line: %d, %s "
                    "store path: %s, prealloc trunk result => "
                    "{total : %d, success: %d}, trunk type => "
                    "{create: %d, reclaim: %d}", __LINE__, ctx->module_name,
                    p->allocator->path_info->store.path.str, p->stat.total,
                    p->stat.success, p->stat.create,
                    p->stat.total - p->stat.create);
        }
    }
}

static int prealloc_trunk(DATrunkPreallocContext *prealloc_ctx,
        TrunkPreallocatorInfo *preallocator)
{
    TrunkPreallocTask *task;

    while ((task=(TrunkPreallocTask *)fast_mblock_alloc_object(
                    &prealloc_ctx->task_allocator)) == NULL &&
            SF_G_CONTINUE_FLAG && g_current_time <
            prealloc_ctx->prealloc_end_time)
    {
        lcp_timedwait_sec(&prealloc_ctx->lcp, 60);
    }

    if (task == NULL) {
        return SF_G_CONTINUE_FLAG ? ETIMEDOUT : EINTR;
    }

    task->preallocator = preallocator;
    preallocator->stat.total++;
    __sync_add_and_fetch(&preallocator->stat.dealings, 1);
    fc_queue_push_silence(&prealloc_ctx->queue, task);
    return 0;
}

static TrunkPreallocatorInfo *prealloc_trunks(
        DATrunkPreallocContext *prealloc_ctx,
        TrunkPreallocatorInfo *head)
{
    TrunkPreallocatorInfo *p;
    TrunkPreallocatorInfo *previous;

    p = head;
    head = previous = NULL;
    while (p != NULL && SF_G_CONTINUE_FLAG) {
        if (da_trunk_allocator_get_freelist_count(p->allocator) +
                __sync_add_and_fetch(&p->stat.dealings, 0) <
                p->allocator->path_info->prealloc_trunks.count)
        {
            if (prealloc_trunk(prealloc_ctx, p) != 0) {
                break;
            }

            if (previous == NULL) {
                head = p;
            } else {
                previous->next = p;
            }

            previous = p;
        }

        p = p->next;
    }

    if (previous != NULL) {
        previous->next = NULL;  //end the chain
    }
    return head;
}

static int do_prealloc_trunks(DATrunkPreallocContext *prealloc_ctx)
{
    TrunkPreallocatorInfo *head;
    struct tm tm_end;
    time_t current_time;
    int count;
    int thread_count;
    int i;

    current_time = g_current_time;
    localtime_r(&current_time, &tm_end);
    tm_end.tm_hour = prealloc_ctx->ctx->storage.
        cfg.prealloc_trunks.end_time.hour;
    tm_end.tm_min = prealloc_ctx->ctx->storage.
        cfg.prealloc_trunks.end_time.minute;
    prealloc_ctx->prealloc_end_time = mktime(&tm_end);
    if (g_current_time > prealloc_ctx->prealloc_end_time) {
        logWarning("file: "__FILE__", line: %d, %s "
                "current time: %ld > end time: %ld, skip prealloc trunks!",
                __LINE__, prealloc_ctx->ctx->module_name, (long)g_current_time,
                (long)prealloc_ctx->prealloc_end_time);
        return 0;
    }

    if ((head=make_preallocator_chain(&prealloc_ctx->
                    preallocator_array, &count)) == NULL)
    {
        logInfo("file: "__FILE__", line: %d, %s "
                "do NOT need prealloc trunks because "
                "all freelists are enough", __LINE__,
                prealloc_ctx->ctx->module_name);
        return 0;
    }

    thread_count = FC_MIN(count, prealloc_ctx->ctx->
            storage.cfg.prealloc_trunks.threads);
    prealloc_ctx->finished = false;
    for (i=0; i<thread_count; i++) {
        fc_thread_pool_run(&prealloc_ctx->thread_pool,
                prealloc_thread_pool_run, prealloc_ctx->thread_args + i);
    }

    do {
        head = prealloc_trunks(prealloc_ctx, head);
    } while (head != NULL && SF_G_CONTINUE_FLAG &&
            g_current_time < prealloc_ctx->prealloc_end_time);

    if (SF_G_CONTINUE_FLAG && g_current_time <
                prealloc_ctx->prealloc_end_time)
    {
        i = 0;
        while (!fc_queue_empty(&prealloc_ctx->queue) && i++ < 300) {
            sleep(1);
        }
    }
    prealloc_ctx->finished = true;

    i = 0;
    while (fc_thread_pool_dealing_count(&prealloc_ctx->thread_pool) > 0) {
        sleep(1);
    }

    log_and_reset_preallocators(prealloc_ctx->ctx,
            &prealloc_ctx->preallocator_array);
    return 0;
}

static int prealloc_trunks_func(void *args)
{
    DATrunkPreallocContext *prealloc_ctx;
    int result;

    prealloc_ctx = args;
    if (prealloc_ctx->in_progress) {
        logWarning("file: "__FILE__", line: %d, %s "
                "prealloc trunks in progress!", __LINE__,
                prealloc_ctx->ctx->module_name);
        return EINPROGRESS;
    }

    prealloc_ctx->in_progress = true;
    result = do_prealloc_trunks(prealloc_ctx);
    prealloc_ctx->in_progress = false;
    return result;
}

static int trunk_prealloc_setup_schedule(DAContext *ctx)
{
    ScheduleArray scheduleArray;
    ScheduleEntry scheduleEntry;

    INIT_SCHEDULE_ENTRY_EX1(scheduleEntry, sched_generate_next_id(),
            ctx->storage.cfg.prealloc_trunks.start_time, 86400,
            prealloc_trunks_func, ctx->trunk_prealloc_ctx, true);
    scheduleArray.entries = &scheduleEntry;
    scheduleArray.count = 1;
    return sched_add_entries(&scheduleArray);
}

static int init_thread_args(DAContext *ctx)
{
    int result;
    int bytes;
    TrunkPreallocThreadArg *p;
    TrunkPreallocThreadArg *end;

    bytes = sizeof(DATrunkPreallocContext) + sizeof(TrunkPreallocThreadArg) *
        ctx->storage.cfg.prealloc_trunks.threads;
    ctx->trunk_prealloc_ctx = fc_malloc(bytes);
    if (ctx->trunk_prealloc_ctx == NULL) {
        return ENOMEM;
    }
    memset(ctx->trunk_prealloc_ctx, 0, bytes);
    ctx->trunk_prealloc_ctx->thread_args = (TrunkPreallocThreadArg *)
        (ctx->trunk_prealloc_ctx + 1);
    ctx->trunk_prealloc_ctx->ctx = ctx;

    end = ctx->trunk_prealloc_ctx->thread_args +
        ctx->storage.cfg.prealloc_trunks.threads;
    for (p=ctx->trunk_prealloc_ctx->thread_args; p<end; p++) {
        p->prealloc_ctx = ctx->trunk_prealloc_ctx;
        p->result = -1;
        if ((result=init_pthread_lock_cond_pair(&p->lcp)) != 0) {
            return result;
        }
    }

    return 0;
}

int da_trunk_prealloc_init(DAContext *ctx)
{
    int result;
    int limit;
    const int max_idle_time = 60;
    const int min_idle_count = 0;
    int alloc_elements_once;
    int alloc_elements_limit;

    if (!ctx->storage.cfg.prealloc_trunks.enabled) {
        return 0;
    }

    if ((result=init_thread_args(ctx)) != 0) {
        return result;
    }

    alloc_elements_once = ctx->storage.cfg.prealloc_trunks.threads * 2;
    alloc_elements_limit = alloc_elements_once;
    if ((result=fast_mblock_init_ex1(&ctx->trunk_prealloc_ctx->task_allocator,
                    "prealloc_task", sizeof(TrunkPreallocTask),
                    alloc_elements_once, alloc_elements_limit,
                    NULL, NULL, true)) != 0)
    {
        return result;
    }
    ctx->trunk_prealloc_ctx->task_allocator.alloc_elements.
        exceed_log_level = LOG_NOTHING;

    if ((result=init_pthread_lock_cond_pair(&ctx->
                    trunk_prealloc_ctx->lcp)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&ctx->trunk_prealloc_ctx->queue, (long)
                    (&((TrunkPreallocTask *)NULL)->next))) != 0)
    {
        return result;
    }

    if ((result=init_preallocator_array(ctx, &ctx->trunk_prealloc_ctx->
                    preallocator_array)) != 0)
    {
        return result;
    }

    limit = ctx->storage.cfg.prealloc_trunks.threads;
    if ((result=fc_thread_pool_init(&ctx->trunk_prealloc_ctx->thread_pool,
                    "prealloc", limit, SF_G_THREAD_STACK_SIZE,
                    max_idle_time, min_idle_count,
                    (bool *)&SF_G_CONTINUE_FLAG)) != 0)
    {
        return result;
    }

    return trunk_prealloc_setup_schedule(ctx);
}
