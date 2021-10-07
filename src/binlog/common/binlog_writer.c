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
#include "fastcommon/pthread_func.h"
#include "fastcommon/fc_atomic.h"
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "sf/sf_func.h"
#include "../common/write_fd_cache.h"
#include "binlog_reader.h"
#include "binlog_writer.h"

#define BINLOG_RECORD_BATCH_SIZE  1024
#define BINLOG_RECORD_MAX_WRITERS    2

#define BINLOG_RECORD_INIT_NODE_CHAINS(pairs) \
    FC_INIT_CHAIN(pairs[0].chain); \
    FC_INIT_CHAIN(pairs[1].chain)

typedef struct binlog_writer_chain_pair {
    DABinlogWriter *writer;
    struct fast_mblock_chain chain;
} BinlogWriterChainPair;

typedef struct binlog_writer_chain_array {
    BinlogWriterChainPair pairs[BINLOG_RECORD_MAX_WRITERS];
    BinlogWriterChainPair *end;
    int count;
} BinlogWriterChainArray;

typedef struct binlog_writer_synchronize_args {
    struct {
        bool done;
        pthread_lock_cond_pair_t lcp;
    } notify;
    DABinlogWriter *writer;
} BWriterSynchronizeArgs;

typedef struct binlog_writer_shrink_task {
    DABinlogWriter *writer;
    void *args;
    struct binlog_writer_shrink_task *next;
} BinlogWriterShrinkTask;

typedef struct {
    struct {
        struct fast_mblock_man sargs;  //synchronize args
        struct fast_mblock_man stask;  //shrink task
    } allocators;
    struct {
        struct fc_queue normal; //update and load
        struct fc_queue shrink; //array shrink
    } queues;
    BinlogWriterChainArray writer_chain_array;
    time_t last_shrink_time;
    volatile int64_t current_version;
    volatile bool running;
} BinlogWriterContext;

static BinlogWriterContext binlog_writer_ctx;

#define WRITER_NORMAL_QUEUE   binlog_writer_ctx.queues.normal
#define WRITER_SHRINK_QUEUE   binlog_writer_ctx.queues.shrink
#define WRITER_CHAIN_ARRAY    binlog_writer_ctx.writer_chain_array

static inline void notify(BWriterSynchronizeArgs *sync_args)
{
    PTHREAD_MUTEX_LOCK(&sync_args->notify.lcp.lock);
    sync_args->notify.done = true;
    pthread_cond_signal(&sync_args->notify.lcp.cond);
    PTHREAD_MUTEX_UNLOCK(&sync_args->notify.lcp.lock);
}

static int log(DABinlogRecord *record, DABinlogWriterCache *cache)
{
    int result;

    if (!DA_BINLOG_ID_TYPE_EQUALS(record->writer->key,
                cache->key) || cache->fd < 0)
    {
        if ((result=da_binlog_writer_cache_write(cache)) != 0) {
            return result;
        }
        cache->key = record->writer->key;
        if ((cache->fd=da_write_fd_cache_get(&cache->key)) < 0) {
            return -1 * cache->fd;
        }
    }

    if (cache->buff_end - cache->current < DA_BINLOG_RECORD_MAX_SIZE) {
        if ((result=da_binlog_writer_cache_write(cache)) != 0) {
            return result;
        }
    }

    cache->current += g_da_write_cache_ctx.type_subdir_array.pairs[
        record->writer->key.type].pack_record(record->args, record->op_type,
                cache->current, cache->buff_end - cache->current);
    return 0;
}

#define dec_writer_updating_count(start, end)  \
    FC_ATOMIC_DEC_EX(((DABinlogWriter *)(*start)-> \
                args)->updating_count, end - start)

static int deal_sorted_record(DABinlogRecord **records,
        const int count)
{
    DABinlogRecord **record;
    DABinlogRecord **end;
    DABinlogWriterCache cache;
    int r;
    int result;

    da_binlog_writer_cache_init(&cache);
    result = 0;
    end = records + count;
    for (record=records; record<end; record++) {
        if ((*record)->op_type == da_binlog_op_type_synchronize) {
            notify((BWriterSynchronizeArgs *)(*record)->args);
        } else {
            if ((result=log(*record, &cache)) != 0) {
                break;
            }
        }
    }

    r = da_binlog_writer_cache_write(&cache);
    if (record == end) {
        return r;
    }

    for (; record<end; record++) {
        if ((*record)->op_type == da_binlog_op_type_synchronize) {
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
        if ((*record)->op_type == da_binlog_op_type_synchronize) {
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
    DABinlogRecord *records[BINLOG_RECORD_MAX_WRITERS *
        BINLOG_RECORD_BATCH_SIZE];
    DABinlogRecord **pp;
    DABinlogRecord *record;
    struct fast_mblock_node *node;
    BinlogWriterChainPair *pair = NULL;

    BINLOG_RECORD_INIT_NODE_CHAINS(WRITER_CHAIN_ARRAY.pairs);
    pp = records;
    record = head;
    do {
        *pp++ = record;

        for (pair = WRITER_CHAIN_ARRAY.pairs;
                pair < WRITER_CHAIN_ARRAY.end;
                pair++)
        {
            if (pair->writer == record->writer) {
                break;
            }
        }

        node = fast_mblock_to_node_ptr(record);
        if (pair->chain.head == NULL) {
            pair->chain.head = node;
        } else {
            pair->chain.tail->next = node;
        }
        pair->chain.tail = node;

        record = record->next;
    } while (record != NULL);

    count = pp - records;
    if (count > 1) {
        qsort(records, count, sizeof(DABinlogRecord *),
                (int (*)(const void *, const void *))record_compare);
    }

    result = deal_sorted_record(records, count);
    dec_updating_count(records, count);

    for (pair=WRITER_CHAIN_ARRAY.pairs; pair<WRITER_CHAIN_ARRAY.end; pair++) {
        if (!FC_IS_CHAIN_EMPTY(pair->chain)) {
            pair->chain.tail->next = NULL;
            fast_mblock_batch_free(&pair->writer->
                    record_allocator, &pair->chain);
        }
    }

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
    result = g_da_write_cache_ctx.type_subdir_array.pairs[
        stask->writer->key.type].shrink(stask->writer, stask->args);
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

int da_binlog_writer_global_init()
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

int da_binlog_writer_init(DABinlogWriter *writer, const int arg_size)
{
    int result;
    int element_size;
    char name[32];

    writer->arg_size = arg_size;
    snprintf(name, sizeof(name), "binlog-record[%d]",
            WRITER_CHAIN_ARRAY.count);
    element_size = sizeof(DABinlogRecord) + arg_size;
    if ((result=fast_mblock_init_ex1(&writer->record_allocator,
                    name, element_size, BINLOG_RECORD_BATCH_SIZE,
                    BINLOG_RECORD_BATCH_SIZE, NULL, NULL, true)) != 0)
    {
        return result;
    }
    fast_mblock_set_need_wait(&writer->record_allocator,
            true, (bool *)&SF_G_CONTINUE_FLAG);

    if (WRITER_CHAIN_ARRAY.count >= BINLOG_RECORD_MAX_WRITERS) {
        logError("file: "__FILE__", line: %d, "
                "too many binlog writers exceeds %d",
                __LINE__, BINLOG_RECORD_MAX_WRITERS);
        return EOVERFLOW;
    }

    WRITER_CHAIN_ARRAY.pairs[WRITER_CHAIN_ARRAY.count++].writer = writer;
    WRITER_CHAIN_ARRAY.end = WRITER_CHAIN_ARRAY.pairs +
        WRITER_CHAIN_ARRAY.count;
    return 0;
}

static inline int push_to_normal_queue(DABinlogWriter *writer,
        const DABinlogOpType op_type, void *args)
{
    DABinlogRecord *record;

    if ((record=(DABinlogRecord *)fast_mblock_alloc_object(
                    &writer->record_allocator)) == NULL)
    {
        return ENOMEM;
    }

    record->writer = writer;
    record->version = __sync_add_and_fetch(&binlog_writer_ctx.
            current_version, 1);
    record->op_type = op_type;
    memcpy(record->args, args, writer->arg_size);
    fc_queue_push(&WRITER_NORMAL_QUEUE, record);
    return 0;
}

int da_binlog_writer_log(DABinlogWriter *writer,
        const DABinlogOpType op_type, void *args)
{
    FC_ATOMIC_INC(writer->updating_count);
    return push_to_normal_queue(writer, op_type, args);
}

int da_binlog_writer_shrink(DABinlogWriter *writer, void *args)
{
    BinlogWriterShrinkTask *stask;

    if ((stask=(BinlogWriterShrinkTask *)fast_mblock_alloc_object(
                    &binlog_writer_ctx.allocators.stask)) == NULL)
    {
        return ENOMEM;
    }

    stask->writer = writer;
    stask->args = args;
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
                da_binlog_op_type_synchronize,
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
