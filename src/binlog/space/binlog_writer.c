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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <pthread.h>
#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/pthread_func.h"
#include "fastcommon/fc_atomic.h"
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "sf/sf_func.h"
#include "../common/write_fd_cache.h"
#include "binlog_reader.h"
#include "binlog_writer.h"

#define BINLOG_RECORD_BATCH_SIZE  1024

typedef struct binlog_writer_synchronize_args {
    struct {
        bool done;
        pthread_lock_cond_pair_t lcp;
    } notify;
    DABinlogWriter *writer;
} BWriterSynchronizeArgs;

typedef struct binlog_writer_shrink_task {
    DABinlogWriter *writer;
    struct binlog_writer_shrink_task *next;
} BinlogWriterShrinkTask;

typedef struct {
    struct {
        struct fast_mblock_man sargs;  //synchronize args
        struct fast_mblock_man record;
        struct fast_mblock_man stask;  //shrink task
    } allocators;
    struct {
        struct fc_queue normal; //update and load
        struct fc_queue shrink; //array shrink
    } queues;
    time_t last_shrink_time;
    volatile int64_t current_version;
    volatile bool running;
} BinlogWriterContext;

typedef struct {
    DABinlogIdTypePair key;
    char buff[8 * 1024];
    char *current;
    char *buff_end;
    int fd;
} BinlogWriterCache;

static BinlogWriterContext binlog_writer_ctx;

#define WRITER_NORMAL_QUEUE   binlog_writer_ctx.queues.normal
#define WRITER_SHRINK_QUEUE   binlog_writer_ctx.queues.shrink

static inline void notify(BWriterSynchronizeArgs *sync_args)
{
    PTHREAD_MUTEX_LOCK(&sync_args->notify.lcp.lock);
    sync_args->notify.done = true;
    pthread_cond_signal(&sync_args->notify.lcp.cond);
    PTHREAD_MUTEX_UNLOCK(&sync_args->notify.lcp.lock);
}

static inline void cache_init(BinlogWriterCache *cache)
{
    cache->key.id = 0;
    cache->key.type = 0;
    cache->fd = -1;
    cache->current = cache->buff;
    cache->buff_end = cache->buff + sizeof(cache->buff);
}

static inline int cache_write(BinlogWriterCache *cache)
{
    int len;

    if ((len=cache->current - cache->buff) == 0) {
        return 0;
    }

    cache->current = cache->buff;
    return fc_safe_write(cache->fd, cache->buff, len);
}

static int log(DABinlogRecord *record, BinlogWriterCache *cache)
{
    int result;

    if (!DA_BINLOG_ID_TYPE_EQUALS(record->writer->key,
                cache->key) || cache->fd < 0)
    {
        if ((result=cache_write(cache)) != 0) {
            return result;
        }
        cache->key = record->writer->key;
        if ((cache->fd=write_fd_cache_get(&cache->key)) < 0) {
            return -1 * cache->fd;
        }
    }

    if (cache->buff_end - cache->current < DA_BINLOG_RECORD_MAX_SIZE) {
        if ((result=cache_write(cache)) != 0) {
            return result;
        }
    }

    cache->current += g_write_cache_ctx.type_subdir_array.pairs[
        record->writer->key.type].pack_record(record->args, cache->current,
                cache->buff_end - cache->current);
    return 0;
}

#define batch_update_index(start, end)  \
    g_write_cache_ctx.type_subdir_array.pairs[(*start)->writer->key.type]. \
    batch_update((*start)->writer, start, end - start)

#define dec_writer_updating_count(start, end)  \
    FC_ATOMIC_DEC_EX(((DABinlogWriter *)(*start)-> \
                args)->updating_count, end - start)

static int deal_sorted_record(DABinlogRecord **records,
        const int count)
{
    DABinlogRecord **record;
    DABinlogRecord **end;
    DABinlogRecord **start;
    BinlogWriterCache cache;
    int r;
    int result;

    cache_init(&cache);
    start = NULL;
    result = 0;
    end = records + count;
    for (record=records; record<end; record++) {
        if ((*record)->op_type == inode_index_op_type_synchronize) {
            if (start != NULL) {
                if ((result=batch_update_index(start, record)) != 0) {
                    break;
                }
                start = NULL;
            }
            notify((BWriterSynchronizeArgs *)(*record)->args);
        } else {
            if (start == NULL) {
                start = record;
            } else if (!DA_BINLOG_ID_TYPE_EQUALS((*record)->
                        writer->key, (*start)->writer->key))
            {
                if ((result=batch_update_index(start, record)) != 0) {
                    break;
                }
                start = record;
            }
            if ((result=log(*record, &cache)) != 0) {
                break;
            }
        }
    }

    r = cache_write(&cache);
    if (record == end) {
        if (start != NULL) {
            if ((result=batch_update_index(start, end)) != 0) {
                return result;
            }
        }
        return r;
    }

    for (; record<end; record++) {
        if ((*record)->op_type == inode_index_op_type_synchronize) {
            notify((BWriterSynchronizeArgs *)(*record)->args);
        }
    }

    return result;
}

static int record_compare(const DABinlogRecord **record1,
        const DABinlogRecord **record2)
{
    int sub;

    sub = fc_compare_int64((*record1)->writer->key.id,
            (*record2)->writer->key.id);
    if (sub != 0) {
        return sub;
    }

    sub = (int)(*record1)->writer->key.type -
        (int)(*record2)->writer->key.type;
    if (sub == 0) {
        return fc_compare_int64((*record1)->version, (*record2)->version);
    } else {
        return sub;
    }
}

static void dec_updating_count(DABinlogRecord **records,
        const int count)
{
    DABinlogRecord **record;
    DABinlogRecord **end;
    DABinlogRecord **start;

    start = NULL;
    end = records + count;
    for (record=records; record<end; record++) {
        if ((*record)->op_type == inode_index_op_type_synchronize) {
            if (start != NULL) {
                dec_writer_updating_count(start, record);
                start = NULL;
            }
        } else {
            if (start == NULL) {
                start = record;
            } else if (!DA_BINLOG_ID_TYPE_EQUALS((*record)->
                        writer->key, (*start)->writer->key))
            {
                dec_writer_updating_count(start, record);
                start = record;
            }
        }
    }

    if (start != NULL) {
        dec_writer_updating_count(start, end);
    }
}

static int deal_binlog_records(DABinlogRecord *head)
{
    int result;
    int count;
    DABinlogRecord *records[BINLOG_RECORD_BATCH_SIZE];
    DABinlogRecord **pp;
    DABinlogRecord *record;
    struct fast_mblock_node *node;
    struct fast_mblock_chain chain;

    chain.head = chain.tail = NULL;
    pp = records;
    record = head;
    do {
        *pp++ = record;

        node = fast_mblock_to_node_ptr(record);
        if (chain.head == NULL) {
            chain.head = node;
        } else {
            chain.tail->next = node;
        }
        chain.tail = node;

        record = record->next;
    } while (record != NULL);
    chain.tail->next = NULL;

    count = pp - records;
    if (count > 1) {
        qsort(records, count, sizeof(DABinlogRecord *),
                (int (*)(const void *, const void *))record_compare);
    }

    result = deal_sorted_record(records, count);
    dec_updating_count(records, count);
    fast_mblock_batch_free(&binlog_writer_ctx.allocators.record, &chain);
    return result;
}

static void deal_shrink_queue()
{
    BinlogWriterShrinkTask *stask;
    int result;

    while (g_current_time - binlog_writer_ctx.last_shrink_time == 0) {
        if (fc_queue_timedpeek_ms(&WRITER_NORMAL_QUEUE, 100) != NULL) {
            break;
        }
    }

    if (g_current_time - binlog_writer_ctx.last_shrink_time == 0) {
        return;
    }

    if ((stask=(BinlogWriterShrinkTask *)fc_queue_try_pop(
                    &WRITER_SHRINK_QUEUE)) == NULL)
    {
        return;
    }
    if (!SF_G_CONTINUE_FLAG) {
        return;
    }

    binlog_writer_ctx.last_shrink_time = g_current_time;

    //write_fd_cache_remove(stask->writer->binlog_id);
    //result = shrink(stask->writer);
    //TODO
    result = 0;
    if (result != 0) {
        logCrit("file: "__FILE__", line: %d, "
                "deal_shrink_queue fail, "
                "program exit!", __LINE__);
        sf_terminate_myself();
    }
}

static void *binlog_writer_func(void *arg)
{
    DABinlogRecord *head;
    bool blocked;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "inode-binlog-writer");
#endif

    binlog_writer_ctx.running = true;
    while (SF_G_CONTINUE_FLAG) {
        blocked = fc_queue_empty(&WRITER_SHRINK_QUEUE);
        if ((head=(DABinlogRecord *)fc_queue_pop_all_ex(
                        &WRITER_NORMAL_QUEUE, blocked)) == NULL)
        {
            deal_shrink_queue();
            continue;
        }

        if (deal_binlog_records(head) != 0) {
            logCrit("file: "__FILE__", line: %d, "
                    "deal_binlog_records fail, "
                    "program exit!", __LINE__);
            sf_terminate_myself();
        }

        if (!blocked || !fc_queue_empty(&WRITER_SHRINK_QUEUE)) {
            deal_shrink_queue();
        }
    }
    binlog_writer_ctx.running = false;
    return NULL;
}

static int sargs_alloc_init_func(BWriterSynchronizeArgs *element, void *args)
{
    return init_pthread_lock_cond_pair(&element->notify.lcp);
}

int da_binlog_writer_init()
{
    int result;
    pthread_t tid;

    if ((result=fast_mblock_init_ex1(&binlog_writer_ctx.allocators.sargs,
                    "inode-sync-args", sizeof(BWriterSynchronizeArgs),
                    1024, 0, (fast_mblock_alloc_init_func)
                    sargs_alloc_init_func, NULL, true)) != 0)
    {
        return result;
    }

    if ((result=fast_mblock_init_ex1(&binlog_writer_ctx.allocators.record,
                    "inode-binlog-record", sizeof(DABinlogRecord),
                    BINLOG_RECORD_BATCH_SIZE, BINLOG_RECORD_BATCH_SIZE,
                    NULL, NULL, true)) != 0)
    {
        return result;
    }
    fast_mblock_set_need_wait(&binlog_writer_ctx.allocators.record,
            true, (bool *)&SF_G_CONTINUE_FLAG);

    if ((result=fast_mblock_init_ex1(&binlog_writer_ctx.allocators.stask,
                    "shrink-task", sizeof(BinlogWriterShrinkTask),
                    1024, 0, NULL, NULL, true)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&WRITER_NORMAL_QUEUE, (unsigned long)
                    (&((DABinlogRecord *)NULL)->next))) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&WRITER_SHRINK_QUEUE, (unsigned long)
                    (&((BinlogWriterShrinkTask *)NULL)->next))) != 0)
    {
        return result;
    }

    return fc_create_thread(&tid, binlog_writer_func,
            NULL, SF_G_THREAD_STACK_SIZE);
}

static inline int push_to_normal_queue(DABinlogWriter *writer,
        const DABinlogOpType op_type, void *args)
{
    DABinlogRecord *record;

    if ((record=(DABinlogRecord *)fast_mblock_alloc_object(
                    &binlog_writer_ctx.allocators.record)) == NULL)
    {
        return ENOMEM;
    }

    record->writer = writer;
    record->version = __sync_add_and_fetch(&binlog_writer_ctx.
            current_version, 1);
    record->op_type = op_type;
    record->args = args;
    fc_queue_push(&WRITER_NORMAL_QUEUE, record);
    return 0;
}

int da_binlog_writer_log(DABinlogWriter *writer, void *args)
{
    FC_ATOMIC_INC(writer->updating_count);
    return push_to_normal_queue(writer,
            inode_index_op_type_log, args);
}

int da_binlog_writer_shrink(DABinlogWriter *writer)
{
    BinlogWriterShrinkTask *stask;

    if ((stask=(BinlogWriterShrinkTask *)fast_mblock_alloc_object(
                    &binlog_writer_ctx.allocators.stask)) == NULL)
    {
        return ENOMEM;
    }

    stask->writer = writer;
    fc_queue_push(&WRITER_SHRINK_QUEUE, stask);
    return 0;
}

int da_binlog_writer_synchronize(DABinlogWriter *writer)
{
    BWriterSynchronizeArgs *sync_args;
    int result;

    if ((sync_args=(BWriterSynchronizeArgs *)fast_mblock_alloc_object(
                    &binlog_writer_ctx.allocators.sargs)) == NULL)
    {
        return ENOMEM;
    }
    sync_args->writer = writer;

    do {
        result = push_to_normal_queue(writer,
                inode_index_op_type_synchronize,
                sync_args);
        if (result != 0) {
            break;
        }

        PTHREAD_MUTEX_LOCK(&sync_args->notify.lcp.lock);
        while (!sync_args->notify.done) {
            pthread_cond_wait(&sync_args->notify.lcp.cond,
                    &sync_args->notify.lcp.lock);
        }
        sync_args->notify.done = false;  /* reset for next */
        PTHREAD_MUTEX_UNLOCK(&sync_args->notify.lcp.lock);
    } while (0);

    fast_mblock_free_object(&binlog_writer_ctx.
            allocators.sargs, sync_args);
    return result;
}

void da_binlog_writer_finish()
{
}
