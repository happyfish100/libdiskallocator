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

#define SKPLIST_INIT_LEVEL_COUNT  4
#define SKPLIST_MAX_LEVEL_COUNT  12

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

    rctx->notify.result = 0;
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
    UniqSkiplistIterator it;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *tail;
    TrunkReclaimBlockInfo *block;

    uniq_skiplist_iterator(rctx->spair.skiplist, &it);
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
    buff = op_ctx->aligned_buffer->buff + op_ctx->aligned_buffer->offset;
#else
    buff = rctx->op_ctx.buff;
#endif

    return trunk_write_thread_by_buff_synchronize(space, buff, &rctx->notify);
}

static int migrate_one_slice(TrunkReclaimContext *rctx,
        DATrunkSpaceLogRecord *record)
{
    int result;
    DATrunkSpaceInfo space;

    if ((result=migrate_prepare(rctx, record)) != 0) {
        return result;
    }

    if ((result=da_slice_read(&rctx->op_ctx, &rctx->notify)) != 0) {
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
    da_release_aio_buffers(&rctx->op_ctx);
#endif

    return 0;
}

static int migrate_one_block(TrunkReclaimContext *rctx,
        TrunkReclaimBlockInfo *block)
{
    DATrunkSpaceLogRecord holder;
    DATrunkSpaceLogRecord *record;
    int result;

    holder = *(block->head);
    holder.storage.length = holder.storage.size = block->total_size;
    if ((result=migrate_one_slice(rctx, &holder)) != 0) {
        return result;
    }

    //TODO
    record = block->head;
    while (record != NULL) {
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
