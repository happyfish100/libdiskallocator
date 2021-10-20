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
#include "../binlog/trunk/trunk_space_log.h"
#include "trunk_reclaim.h"

#define SKPLIST_INIT_LEVEL_COUNT  4
#define SKPLIST_MAX_LEVEL_COUNT  12

static void reclaim_slice_rw_done_callback(DASliceOpContext *op_ctx,
        TrunkReclaimContext *rctx)
{
    PTHREAD_MUTEX_LOCK(&rctx->notify.lcp.lock);
    rctx->notify.finished = true;
    pthread_cond_signal(&rctx->notify.lcp.cond);
    PTHREAD_MUTEX_UNLOCK(&rctx->notify.lcp.lock);
}

static int space_log_record_alloc_init(void *element, void *args)
{
    ((DATrunkSpaceLogRecord *)element)->allocator =
        (struct fast_mblock_man *)args;
    return 0;
}

static int compare_by_trunk_offset(const DATrunkSpaceLogRecord *s1,
        const DATrunkSpaceLogRecord *s2)
{
    return fc_compare_int64(s1->storage.offset, s2->storage.offset);
}

static void space_log_record_free_func(void *ptr, const int delay_seconds)
{
    fast_mblock_free_object(((DATrunkSpaceLogRecord *)ptr)->allocator, ptr);
}

int trunk_reclaim_init_ctx(TrunkReclaimContext *rctx)
{
    const int min_alloc_elements_once = 4;
    const int delay_free_seconds = 0;
    int result;

#ifdef OS_LINUX
    rctx->op_ctx.info.buffer_type = da_buffer_type_array;
    rctx->buffer_size = 0;
    rctx->op_ctx.info.buff = NULL;
#else
    rctx->buffer_size = 256 * 1024;
    rctx->op_ctx.info.buff = (char *)fc_malloc(rctx->buffer_size);
    if (rctx->op_ctx.info.buff == NULL) {
        return ENOMEM;
    }
#endif

    if ((result=fast_mblock_init_ex1(&rctx->record_allocator,
                    "space-log-record", sizeof(DATrunkSpaceLogRecord),
                    8 * 1024, 0, space_log_record_alloc_init,
                    &rctx->record_allocator, false)) != 0)
    {
        return result;
    }

    if ((result=uniq_skiplist_init_pair(&rctx->spair, SKPLIST_INIT_LEVEL_COUNT,
                    SKPLIST_MAX_LEVEL_COUNT, (skiplist_compare_func)
                    compare_by_trunk_offset, space_log_record_free_func,
                    min_alloc_elements_once, delay_free_seconds)) != 0)
    {
        return result;
    }

    if ((result=init_pthread_lock_cond_pair(&rctx->notify.lcp)) != 0) {
        return result;
    }

    rctx->notify.finished = false;
    rctx->op_ctx.rw_done_callback = (da_rw_done_callback_func)
        reclaim_slice_rw_done_callback;
    rctx->op_ctx.arg = rctx;
    return 0;
}

static int realloc_rb_array(TrunkReclaimBlockArray *array,
        const int target_count)
{
    TrunkReclaimBlockInfo *blocks;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 1024;
    while (new_alloc < target_count) {
        new_alloc *= 2;
    }
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

static int parse_to_rs_array(string_t *content,
        TrunkReclaimContext *rctx, char *error_info)
{
    int result;
    bool need_free;
    string_t line;
    char *line_start;
    char *buff_end;
    char *line_end;
    DATrunkSpaceLogRecord *record;

    result = 0;
    line_start = content->str;
    buff_end = content->str + content->len;
    while (line_start < buff_end) {
        line_end = (char *)memchr(line_start, '\n', buff_end - line_start);
        if (line_end == NULL) {
            break;
        }

        record = (DATrunkSpaceLogRecord *)fast_mblock_alloc_object(
                &rctx->record_allocator);
        if (record == NULL) {
            sprintf(error_info, "alloc record object fail "
                    "because out of memory");
            return ENOMEM;
        }

        ++line_end;
        line.str = line_start;
        line.len = line_end - line_start;
        if ((result=da_trunk_space_log_unpack(&line,
                        record, error_info)) != 0)
        {
            return result;
        }

        if (record->op_type == da_binlog_op_type_consume_space) {
            result = uniq_skiplist_insert(rctx->spair.skiplist, record);
            need_free = (result != 0);
        } else {
            result = uniq_skiplist_delete(rctx->spair.skiplist, record);
            need_free = true;
        }

        if (need_free) {
            fast_mblock_free_object(&rctx->record_allocator, record);
        }

        if (result == ENOMEM) {
            sprintf(error_info, "alloc skiplist node fail "
                    "because out of memory");
            return result;
        }

        line_start = line_end;
    }

    return 0;
}

static int load_from_space_log(DATrunkAllocator *allocator,
        DATrunkFileInfo *trunk, TrunkReclaimContext *rctx)
{
    int result;
    int fd;
    string_t content;
    char space_log_filename[PATH_MAX];
    char buff[64 * 1024];
    char error_info[256];

    dio_get_space_log_filename(trunk->id_info.id,
            space_log_filename, sizeof(space_log_filename));
    if ((fd=open(space_log_filename, O_RDONLY)) < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, space_log_filename, result, STRERROR(result));
        return result;
    }

    result = 0;
    *error_info = '\0';
    content.str = buff;
    while ((content.len=fc_read_lines(fd, buff, sizeof(buff))) > 0) {
        if ((result=parse_to_rs_array(&content, rctx, error_info)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "parse file: %s fail, errno: %d, error info: %s",
                    __LINE__, space_log_filename, result, error_info);
            break;
        }
    }

    if (content.len < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "read from file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, space_log_filename, result, STRERROR(result));
    }
    close(fd);

    return result;
}

static int combine_to_rb_array(TrunkReclaimContext *rctx,
        TrunkReclaimBlockArray *barray)
{
    int result;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *tail;
    TrunkReclaimBlockInfo *block;

    block = barray->blocks;
    /*
    while (record < send) {

    if (barray->alloc <= barray->count) {
        if ((result=realloc_rb_array(barray, sarray->count)) != 0) {
            return result;
        }
    }

        block->head = tail = record;
        record++;

        //TODO
        while (record < send && 1 == 0)
        {
            if (tail->storage.offset + tail->storage.length ==
                    record->storage.offset)
            {  //combine slices
                tail->storage.length += record->storage.length;
            } else {
                tail->next = record;
                tail = record;
            }
            record++;
        }

        block++;
        tail->next = NULL;  //end of record chain
    }
    */

    barray->count = block - barray->blocks;
    return 0;
}

static int migrate_prepare(TrunkReclaimContext *rctx,
        DATrunkSpaceLogRecord *record)
{
    rctx->op_ctx.info.record = record;

#ifdef OS_LINUX
#else
    if (rctx->buffer_size < record->storage.length) {
        char *buff;
        int buffer_size;

        buffer_size = rctx->buffer_size * 2;
        while (buffer_size < record->storage.length) {
            buffer_size *= 2;
        }
        buff = (char *)fc_malloc(buffer_size);
        if (buff == NULL) {
            return ENOMEM;
        }

        free(rctx->op_ctx.info.buff);
        rctx->op_ctx.info.buff = buff;
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
            "oid: %"PRId64", fid: %u, slice offset: %d, length: %d, "
            "errno: %d, error info: %s", __LINE__, caption,
            op_ctx->info.record->oid, op_ctx->info.record->fid,
            op_ctx->info.record->storage.offset,
            op_ctx->info.record->storage.length,
            result, STRERROR(result));
}

static int migrate_one_slice(TrunkReclaimContext *rctx,
        DATrunkSpaceLogRecord *record)
{
    int result;

    if ((result=migrate_prepare(rctx, record)) != 0) {
        return result;
    }

    /*
    if ((result=da_slice_read(&rctx->op_ctx)) == 0) {
        PTHREAD_MUTEX_LOCK(&rctx->notify.lcp.lock);
        while (!rctx->notify.finished && SF_G_CONTINUE_FLAG) {
            pthread_cond_wait(&rctx->notify.lcp.cond,
                    &rctx->notify.lcp.lock);
        }
        result = rctx->notify.finished ? rctx->op_ctx.result : EINTR;
        rctx->notify.finished = false;  //reset for next call
        PTHREAD_MUTEX_UNLOCK(&rctx->notify.lcp.lock);
    }
    */

    if (result != 0) {
        log_rw_error(&rctx->op_ctx, result, ENOENT, "read");
        return result == ENOENT ? 0 : result;
    }

    rctx->op_ctx.info.record->storage.length = rctx->op_ctx.done_bytes;
    /*
    if ((result=da_slice_write(&rctx->op_ctx)) == 0) {
        PTHREAD_MUTEX_LOCK(&rctx->notify.lcp.lock);
        while (!rctx->notify.finished && SF_G_CONTINUE_FLAG) {
            pthread_cond_wait(&rctx->notify.lcp.cond,
                    &rctx->notify.lcp.lock);
        }
        if (rctx->notify.finished) {
            rctx->notify.finished = false;  //reset for next call
        } else {
            rctx->op_ctx.result = EINTR;
        }
        PTHREAD_MUTEX_UNLOCK(&rctx->notify.lcp.lock);
    } else {
        rctx->op_ctx.result = result;
    }
     */

#ifdef OS_LINUX
    da_release_aio_buffers(&rctx->op_ctx);
#endif

    if (rctx->op_ctx.result != 0) {
        log_rw_error(&rctx->op_ctx, rctx->op_ctx.result, 0, "write");
        return rctx->op_ctx.result;
    }

    //TODO
    return 0;
}

static int migrate_one_block(TrunkReclaimContext *rctx,
        TrunkReclaimBlockInfo *block)
{
    DATrunkSpaceLogRecord *record;
    int result;

    record = block->head;
    while (record != NULL) {
        if ((result=migrate_one_slice(rctx, record)) != 0) {
            return result;
        }
        record = record->next;
    }

    return 0;
}

static int migrate_blocks(TrunkReclaimContext *rctx)
{
    TrunkReclaimBlockInfo *block;
    TrunkReclaimBlockInfo *bend;
    int result;

    bend = rctx->barray.blocks + rctx->barray.count;
    for (block=rctx->barray.blocks; block<bend; block++) {
        if ((result=migrate_one_block(rctx, block)) != 0) {
            return result;
        }
    }

    return 0;
}

int trunk_reclaim(DATrunkAllocator *allocator, DATrunkFileInfo *trunk,
        TrunkReclaimContext *rctx)
{
    int result;

    if (uniq_skiplist_new_by_pair(&rctx->spair,
                SKPLIST_INIT_LEVEL_COUNT) == NULL)
    {
        return ENOMEM;
    }

    do {
        if ((result=load_from_space_log(allocator, trunk, rctx)) != 0) {
            break;
        }

        if ((result=combine_to_rb_array(rctx, &rctx->barray)) != 0) {
            break;
        }

        if ((result=migrate_blocks(rctx)) != 0) {
            break;
        }
    } while (0);

    uniq_skiplist_free_by_pair(&rctx->spair);
    return result;
}
