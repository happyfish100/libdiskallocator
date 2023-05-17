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
#include <fcntl.h>
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_buffer.h"
#include "sf/sf_global.h"
#include "../../global.h"
#include "../../storage_allocator.h"
#include "../../dio/trunk_fd_cache.h"
#include "trunk_index.h"
#include "trunk_space_log.h"

#define RECORD_PTR_ARRAY  ctx->space_log_ctx.record_array
#define FD_CACHE_CTX      ctx->space_log_ctx.fd_cache_ctx

#define SPACE_LOG_MAX_FIELD_COUNT        11

#define SPACE_LOG_FIELD_INDEX_TIMESTAMP   0
#define SPACE_LOG_FIELD_INDEX_VERSION     1
#define SPACE_LOG_FIELD_INDEX_INODE       2
#define SPACE_LOG_FIELD_INDEX_FINDEX      3
#define SPACE_LOG_FIELD_INDEX_OP_TYPE     4
#define SPACE_LOG_FIELD_INDEX_TRUNK_ID    5
#define SPACE_LOG_FIELD_INDEX_LENGTH      6
#define SPACE_LOG_FIELD_INDEX_OFFSET      7
#define SPACE_LOG_FIELD_INDEX_SIZE        8
#define SPACE_LOG_FIELD_INDEX_SLICE_TYPE  9
#define SPACE_LOG_FIELD_INDEX_EXTRA      10

int da_trunk_space_log_unpack(const string_t *line,
        DATrunkSpaceLogRecord *record, char *error_info,
        const bool have_extra_field)
{
    int count;
    int expect;
    bool have_slice_type;
    char size_endchr;
    char *endptr;
    string_t cols[SPACE_LOG_MAX_FIELD_COUNT];

    have_slice_type = true;
    size_endchr = ' ';
    if (have_extra_field) {
        expect = SPACE_LOG_MAX_FIELD_COUNT;
    } else {
        expect = SPACE_LOG_MAX_FIELD_COUNT - 1;
    }
    count = split_string_ex(line, ' ', cols,
            SPACE_LOG_MAX_FIELD_COUNT, false);
    if (count != expect) {
        if (!have_extra_field && (count == expect - 1)) {  //compatible with old format
            have_slice_type = false;
            size_endchr = '\n';
        } else {
            sprintf(error_info, "record count: %d != %d", count, expect);
            return EINVAL;
        }
    }

    SF_BINLOG_PARSE_INT_SILENCE(record->storage.version,
            "version", SPACE_LOG_FIELD_INDEX_VERSION, ' ', 0);
    SF_BINLOG_PARSE_INT_SILENCE(record->oid, "object ID",
            SPACE_LOG_FIELD_INDEX_INODE, ' ', 0);
    record->op_type = cols[SPACE_LOG_FIELD_INDEX_OP_TYPE].str[0];
    if (!(record->op_type == da_binlog_op_type_consume_space ||
                record->op_type == da_binlog_op_type_reclaim_space))
    {
        sprintf(error_info, "unkown op type: %d (0x%02x)",
                record->op_type, (unsigned char)record->op_type);
        return EINVAL;
    }
    SF_BINLOG_PARSE_INT_SILENCE(record->fid, "field index",
            SPACE_LOG_FIELD_INDEX_FINDEX, ' ', 0);
    SF_BINLOG_PARSE_INT_SILENCE(record->storage.trunk_id,
            "trunk id", SPACE_LOG_FIELD_INDEX_TRUNK_ID, ' ', 0);
    SF_BINLOG_PARSE_INT_SILENCE(record->storage.length,
            "data length", SPACE_LOG_FIELD_INDEX_LENGTH, ' ', 0);
    SF_BINLOG_PARSE_INT_SILENCE(record->storage.offset, "offset",
            SPACE_LOG_FIELD_INDEX_OFFSET, ' ', 0);
    SF_BINLOG_PARSE_INT_SILENCE(record->storage.size, "size",
            SPACE_LOG_FIELD_INDEX_SIZE, size_endchr, 0);
    if (have_slice_type) {
        record->slice_type = cols[SPACE_LOG_FIELD_INDEX_SLICE_TYPE].str[0];
        if (!(record->slice_type == DA_SLICE_TYPE_FILE ||
                    record->slice_type == DA_SLICE_TYPE_ALLOC ||
                    record->slice_type == DA_SLICE_TYPE_CACHE))
        {
            sprintf(error_info, "unkown slice type: %d (0x%02x)",
                    record->slice_type, (unsigned char)record->slice_type);
            return EINVAL;
        }
    } else {
        record->slice_type = DA_SLICE_TYPE_FILE;
    }
    if (have_extra_field) {
        SF_BINLOG_PARSE_INT_SILENCE(record->extra, "extra",
                SPACE_LOG_FIELD_INDEX_EXTRA, '\n', 0);
    }
    return 0;
}

static int realloc_record_array(DATrunkSpaceLogRecordArray *array)
{
    DATrunkSpaceLogRecord **records;
    int new_alloc;
    int bytes;

    new_alloc = (array->alloc > 0) ? 2 * array->alloc : 8 * 1024;
    bytes = sizeof(DATrunkSpaceLogRecord *) * new_alloc;
    records = (DATrunkSpaceLogRecord **)fc_malloc(bytes);
    if (records == NULL) {
        return ENOMEM;
    }

    if (array->count > 0) {
        memcpy(records, array->records, array->count *
                sizeof(DATrunkSpaceLogRecord *));
        free(array->records);
    }

    array->alloc = new_alloc;
    array->records = records;
    return 0;
}

static int record_ptr_compare(const DATrunkSpaceLogRecord **record1,
        const DATrunkSpaceLogRecord **record2)
{
    int sub;

    if ((sub=fc_compare_int64((*record1)->storage.trunk_id,
                    (*record2)->storage.trunk_id)) != 0)
    {
        return sub;
    }

    return fc_compare_int64((*record1)->version, (*record2)->version);
}

static int chain_to_array(DAContext *ctx, DATrunkSpaceLogRecord *head,
        int *notify_count)
{
    int result;
    DATrunkSpaceLogRecord *record;

    *notify_count = 0;
    RECORD_PTR_ARRAY.count = 0;
    record = head;
    do {
        if (RECORD_PTR_ARRAY.count == RECORD_PTR_ARRAY.alloc) {
            if ((result=realloc_record_array(&RECORD_PTR_ARRAY)) != 0) {
                return result;
            }
        }

        RECORD_PTR_ARRAY.records[RECORD_PTR_ARRAY.count++] = record;
        if (record->op_type != da_binlog_op_type_unlink_binlog) {
            ctx->trunk_index_ctx.last_version = record->storage.version;
            ++(*notify_count);
        }
    } while ((record=record->next) != NULL);

    if (RECORD_PTR_ARRAY.count > 1) {
        qsort(RECORD_PTR_ARRAY.records, RECORD_PTR_ARRAY.count,
                sizeof(DATrunkSpaceLogRecord *), (int (*)(const void *,
                        const void *))record_ptr_compare);
    }

    return 0;
}

int da_trunk_space_log_calc_version(DAContext *ctx,
        const uint64_t trunk_id, int64_t *version)
{
    int result;
    struct stat buf;
    char space_log_filename[PATH_MAX];

    dio_get_space_log_filename(ctx, trunk_id, space_log_filename,
            sizeof(space_log_filename));
    if (stat(space_log_filename, &buf) < 0) {
        result = errno != 0 ? errno : EACCES;
        if (result == ENOENT) {
            *version = 0;
            return 0;
        }

        logError("file: "__FILE__", line: %d, %s "
                "stat file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, ctx->module_name, space_log_filename,
                result, STRERROR(result));
        return result;
    }

    *version = ((buf.st_size << 32) | buf.st_mtime);
    return 0;
}

static int get_write_fd(DAContext *ctx, const uint64_t trunk_id, int *fd)
{
    const int flags = O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC;
    int result;
    char space_log_filename[PATH_MAX];

    if ((*fd=da_trunk_fd_cache_get(&FD_CACHE_CTX, trunk_id)) >= 0) {
        return 0;
    }

    dio_get_space_log_filename(ctx, trunk_id, space_log_filename,
            sizeof(space_log_filename));
    if ((*fd=open(space_log_filename, flags, 0644)) < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, ctx->module_name, space_log_filename,
                result, STRERROR(result));
        return result;
    }

    da_trunk_fd_cache_add(&FD_CACHE_CTX, trunk_id, *fd);
    return 0;
}

static int do_write_to_file(DAContext *ctx, const uint64_t trunk_id,
        int fd, char *buff, const int len, const bool flush)
{
    int result;
    char space_log_filename[PATH_MAX];

    if (fc_safe_write(fd, buff, len) != len) {
        result = errno != 0 ? errno : EIO;
        dio_get_space_log_filename(ctx, trunk_id, space_log_filename,
                sizeof(space_log_filename));
        logError("file: "__FILE__", line: %d, %s "
                "write to space log file \"%s\" fail, "
                "errno: %d, error info: %s", __LINE__, ctx->module_name,
                space_log_filename, result, STRERROR(result));
        return result;
    }

    ctx->space_log_ctx.written_count++;
    if (flush && (ctx->storage.cfg.fsync_every_n_writes > 0 && ctx->
                space_log_ctx.written_count >= ctx->storage.cfg.
                fsync_every_n_writes))
    {
        ctx->space_log_ctx.written_count = 0;
        if (fsync(fd) != 0) {
            result = errno != 0 ? errno : EIO;
            dio_get_space_log_filename(ctx, trunk_id, space_log_filename,
                    sizeof(space_log_filename));
            logError("file: "__FILE__", line: %d, %s "
                    "fsync to space log file \"%s\" fail, "
                    "errno: %d, error info: %s", __LINE__, ctx->module_name,
                    space_log_filename, result, STRERROR(result));
            return result;
        }
    }

    return 0;
}

static int write_to_log_file(DAContext *ctx,
        DATrunkSpaceLogRecord **start,
        DATrunkSpaceLogRecord **end)
{
    int result;
    int fd;
    int dec_count;
    int skip_count;
    DATrunkSpaceLogRecord **current;
    DATrunkFileInfo *trunk;

    if ((result=get_write_fd(ctx, (*start)->storage.trunk_id, &fd)) != 0) {
        return result;
    }

    ctx->space_log_ctx.buffer.length = 0;
    dec_count = skip_count = 0;
    do {
        if ((*start)->trunk != NULL) {
            trunk = (*start)->trunk;
        } else if ((trunk=da_trunk_hashtable_get(&ctx->trunk_htable_ctx,
                        (*start)->storage.trunk_id)) == NULL)
        {
            result = ENOENT;
            break;
        }

        for (current=start; current<end; current++) {
            if ((*current)->trunk != NULL) {
                (*current)->trunk = NULL;
                ++dec_count;
            }

            if ((*current)->version <= trunk->start_version) {
                int log_level;
                if ((*current)->op_type == da_binlog_op_type_consume_space) {
                    log_level = LOG_ERR;
                } else {
                    log_level = LOG_WARNING;
                }
                log_it_ex(&g_log_context, log_level,
                        "file: "__FILE__", line: %d, %s "
                        "trunk id: %"PRId64", op type: %c, record version: "
                        "%"PRId64" <= trunk start version: %"PRId64", skip!",
                        __LINE__, ctx->module_name, trunk->id_info.id,
                        (*current)->op_type, (*current)->version,
                        trunk->start_version);
                ++skip_count;
                continue;
            }

            if (ctx->space_log_ctx.buffer.alloc_size -
                    ctx->space_log_ctx.buffer.length < 128)
            {
                if ((result=do_write_to_file(ctx, (*start)->storage.trunk_id,
                                fd, ctx->space_log_ctx.buffer.data,
                                ctx->space_log_ctx.buffer.length,
                                false)) != 0)
                {
                    break;
                }

                ctx->space_log_ctx.buffer.length = 0;
            }

            da_trunk_space_log_pack(*current, &ctx->space_log_ctx.buffer,
                    ctx->storage.have_extra_field);
        }

        if (ctx->space_log_ctx.buffer.length > 0 && (result=do_write_to_file(
                        ctx, (*start)->storage.trunk_id, fd, ctx->
                        space_log_ctx.buffer.data, ctx->space_log_ctx.
                        buffer.length, true)) != 0)
        {
            break;
        }

        if (dec_count > 0) {
            da_trunk_freelist_decrease_writing_count_ex(trunk, dec_count);
            /*
            logInfo("file: "__FILE__", line: %d, %s "
                    "trunk id: %"PRId64", dec_count: %d, writing_count: %d",
                    __LINE__, ctx->module_name, trunk->id_info.id,
                    dec_count, FC_ATOMIC_GET(trunk->writing_count));
                    */
        }

        if (skip_count == 0) {
            result = da_trunk_allocator_deal_space_changes(ctx,
                    trunk, start, end - start);
        } else {
            for (current=start; current<end; current++) {
                if ((*current)->version > trunk->start_version) {
                    if ((result=da_trunk_allocator_deal_space_changes(
                                    ctx, trunk, current, 1)) != 0)
                    {
                        break;
                    }
                }
            }
        }

    } while (0);

    return result;
}

static inline int da_trunk_space_log_unlink(DAContext *ctx,
        const uint64_t trunk_id)
{
    char space_log_filename[PATH_MAX];

    dio_get_space_log_filename(ctx, trunk_id, space_log_filename,
            sizeof(space_log_filename));
    return fc_delete_file_ex(space_log_filename, "trunk space log");
}

static inline int deal_trunk_records(DAContext *ctx,
        DATrunkSpaceLogRecord **start,
        DATrunkSpaceLogRecord **end)
{
    int result;
    int64_t used_bytes;
    DATrunkFileInfo *trunk;

    if ((*start)->op_type == da_binlog_op_type_unlink_binlog) {
        trunk = (*start)->trunk;
        (*start)->trunk = NULL;

        trunk->start_version = (*start)->storage.version;
        da_trunk_fd_cache_delete(&FD_CACHE_CTX, trunk->id_info.id);
        if ((used_bytes=FC_ATOMIC_GET(trunk->used.bytes)) != 0) {
            char space_log_filename[PATH_MAX];
            char bak_filename[PATH_MAX];
            int log_level;

            if (used_bytes < 0) {
                dio_get_space_log_filename(ctx, trunk->id_info.id,
                        space_log_filename, sizeof(space_log_filename));
                snprintf(bak_filename, sizeof(bak_filename), "%s.%ld",
                        space_log_filename, (long)g_current_time);
                result = fc_check_rename(space_log_filename, bak_filename);
                log_level = LOG_ERR;
            } else {
                result = da_trunk_space_log_unlink(ctx, trunk->id_info.id);
                log_level = LOG_WARNING;
            }
            log_it_ex(&g_log_context, log_level,
                    "file: "__FILE__", line: %d, %s "
                    "trunk id: %"PRId64", slice count: %d, used bytes: "
                    "%"PRId64" != 0", __LINE__, ctx->module_name,
                    trunk->id_info.id, trunk->used.count,
                    used_bytes);
        } else {
            result = da_trunk_space_log_unlink(ctx, trunk->id_info.id);
        }
        sf_synchronize_finished_notify((*start)->sctx, result);
        return result;
    } else {
        return write_to_log_file(ctx, start, end);
    }
}

static int deal_sorted_array(DAContext *ctx,
        DATrunkSpaceLogRecordArray *array)
{
    int result;
    DATrunkSpaceLogRecord **start;
    DATrunkSpaceLogRecord **end;
    DATrunkSpaceLogRecord **current;

    start = array->records;
    current = start;
    end = array->records + array->count;
    while (++current < end) {
        if ((*current)->storage.trunk_id != (*start)->storage.trunk_id ||
                (*current)->op_type == da_binlog_op_type_unlink_binlog)
        {
            if ((result=deal_trunk_records(ctx, start, current)) != 0) {
                return result;
            }
            start = current;
        }
    }

    return deal_trunk_records(ctx, start, current);
}

static int deal_all_records(DAContext *ctx, DATrunkSpaceLogRecord *head)
{
    int result;
    int notify_count;

    if ((result=chain_to_array(ctx, head, &notify_count)) != 0) {
        return result;
    }

    result = deal_sorted_array(ctx, &RECORD_PTR_ARRAY);
    if (notify_count > 0) {
        sf_synchronize_counter_notify(&ctx->space_log_ctx.
                notify, notify_count);
    }

    fast_mblock_free_objects(&ctx->space_log_ctx.reader.record_allocator,
            (void **)RECORD_PTR_ARRAY.records, RECORD_PTR_ARRAY.count);
    return result;
}

static int redo_by_trunk(DAContext *ctx, DATrunkSpaceLogRecord **start,
        DATrunkSpaceLogRecord **end, int *redo_count)
{
#define FIXED_RECORD_COUNT   1024
    int result;
    int count;
    DATrunkSpaceLogRecord *fixed[FIXED_RECORD_COUNT];
    DATrunkSpaceLogRecord **current;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *found;
    UniqSkiplist *skiplist;
    DATrunkFileInfo *trunk;
    DATrunkSpaceLogRecordArray array;

    if (ctx->storage.skip_path_index >= 0) {
        if ((trunk=da_trunk_hashtable_get_ex(&ctx->trunk_htable_ctx,
                        (*start)->storage.trunk_id, LOG_NOTHING)) == NULL)
        {
            return 0;
        }

        if (trunk->allocator->path_info->store.index ==
                ctx->storage.skip_path_index)
        {
            return 0;
        }
    }

    if ((result=da_space_log_reader_load(&ctx->space_log_ctx.reader,
                    (*start)->storage.trunk_id, &skiplist)) != 0)
    {
        return result;
    }

    if (skiplist == NULL) {
        skiplist = uniq_skiplist_new(&ctx->space_log_ctx.reader.
                factory, DA_SPACE_SKPLIST_INIT_LEVEL_COUNT);
        if (skiplist == NULL) {
            return ENOMEM;
        }
    }

    count = end - start;
    if (count <= FIXED_RECORD_COUNT) {
        array.records = fixed;
        array.alloc = FIXED_RECORD_COUNT;
    } else {
        array.alloc = count;
        array.records = (DATrunkSpaceLogRecord **)fc_malloc(
                sizeof(DATrunkSpaceLogRecord *) * array.alloc);
        if (array.records == NULL) {
            return ENOMEM;
        }
    }

    array.count = 0;
    for (current=start; current<end; current++) {
        if ((*current)->op_type == da_binlog_op_type_consume_space) {
            if (uniq_skiplist_find(skiplist, *current) == NULL) {
                if ((record=da_trunk_space_log_alloc_record(ctx)) == NULL) {
                    return ENOMEM;
                }

                record->storage = (*current)->storage;
                if ((result=uniq_skiplist_insert(skiplist, record)) != 0) {
                    return ENOMEM;
                }
                array.records[array.count++] = *current;
            }
        } else {  //da_binlog_op_type_reclaim_space
            if ((found=uniq_skiplist_find(skiplist, *current)) != NULL) {
                if (found->storage.size == (*current)->storage.size) {
                    uniq_skiplist_delete(skiplist, *current);
                    array.records[array.count++] = *current;
                }
            }
        }
    }

    if (array.count > 0) {
        *redo_count += array.count;
        result = write_to_log_file(ctx, array.records,
                array.records + array.count);
    }

    if (array.records != fixed) {
        free(array.records);
    }
    uniq_skiplist_free(skiplist);

    return result;
}

static int redo_by_array(DAContext *ctx, DATrunkSpaceLogRecordArray *array)
{
    int result;
    int redo_count;
    int total_redo_count;
    DATrunkSpaceLogRecord **start;
    DATrunkSpaceLogRecord **end;
    DATrunkSpaceLogRecord **current;

    total_redo_count = 0;
    redo_count = 0;
    start = array->records;
    current = start;
    end = array->records + array->count;
    while (++current < end) {
        if ((*current)->storage.trunk_id != (*start)->storage.trunk_id) {
            if ((result=redo_by_trunk(ctx, start, current, &redo_count)) != 0) {
                return result;
            }
            total_redo_count += redo_count;
            start = current;
        }
    }

    if ((result=redo_by_trunk(ctx, start, current, &redo_count)) != 0) {
        return result;
    }
    total_redo_count += redo_count;
    logInfo("file: "__FILE__", line: %d, %s "
            "record count: %d, redo count: %d", __LINE__,
            ctx->module_name, array->count, total_redo_count);

    return 0;
}

int da_trunk_space_log_redo_by_chain(DAContext *ctx,
        struct fc_queue_info *chain)
{
    int result;
    int notify_count;

    if (chain->head == NULL) {
        return 0;
    }

    if ((result=chain_to_array(ctx, chain->head, &notify_count)) != 0) {
        return result;
    }

    result = redo_by_array(ctx, &RECORD_PTR_ARRAY);
    fast_mblock_free_objects(&ctx->space_log_ctx.reader.record_allocator,
            (void **)RECORD_PTR_ARRAY.records, RECORD_PTR_ARRAY.count);
    return result;
}

int da_trunk_space_log_redo_by_file(DAContext *ctx,
        const char *space_log_filename)
{
    struct fc_queue_info chain;
    int result;

    if ((result=da_space_log_reader_load_to_chain(&ctx->space_log_ctx.
                    reader, space_log_filename, &chain)) != 0)
    {
        return result;
    }

    return da_trunk_space_log_redo_by_chain(ctx, &chain);
}

static int dump_trunk_indexes(DAContext *ctx)
{
    int result;
    if ((result=da_storage_allocator_trunks_to_array(ctx,
                    &ctx->trunk_index_ctx.index_array)) != 0)
    {
        return result;
    }

    return da_trunk_index_save(ctx);
}

static int set_trunk_by_space_log(DAContext *ctx, DATrunkFileInfo *trunk)
{
    int result;
    UniqSkiplist *skiplist;
    UniqSkiplistIterator it;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *last;

    if ((result=da_space_log_reader_load(&ctx->space_log_ctx.reader,
                    trunk->id_info.id, &skiplist)) != 0)
    {
        return result;
    }

    trunk->used.count = 0;
    trunk->used.bytes = 0;
    if (skiplist == NULL) {
        trunk->free_start = 0;
        return 0;
    }

    last = NULL;
    uniq_skiplist_iterator(skiplist, &it);
    while ((record=uniq_skiplist_next(&it)) != NULL) {
        trunk->used.count++;
        trunk->used.bytes += record->storage.size;
        last = record;
    }

    if (last != NULL) {
        trunk->free_start = last->storage.offset + last->storage.size;
    } else {
        trunk->free_start = 0;
    }

    uniq_skiplist_free(skiplist);
    return 0;
}

static int load_trunk_indexes(DAContext *ctx)
{
    int result;
    int64_t version;
    char filename[PATH_MAX];
    DATrunkFileInfo *trunk;
    DATrunkIndexRecord *index;
    DATrunkIndexRecord *end;
    DATrunkHashtableIterator it;

    if (ctx->storage.skip_path_index >= 0) {
        da_trunk_index_get_filename(ctx, filename, sizeof(filename));
        if ((result=fc_delete_file_ex(filename, "trunk index")) != 0) {
            return result;
        }
    }
    if ((result=da_trunk_index_load(ctx)) != 0) {
        return result;
    }

    end = (DATrunkIndexRecord *)ctx->trunk_index_ctx.index_array.indexes +
        ctx->trunk_index_ctx.index_array.count;
    for (index=ctx->trunk_index_ctx.index_array.indexes; index<end; index++) {
        if ((trunk=da_trunk_hashtable_get(&ctx->trunk_htable_ctx,
                        index->trunk_id)) == NULL)
        {
            return ENOENT;
        }

        da_trunk_space_log_calc_version(ctx, index->trunk_id, &version);
        if (index->version == version) {
            trunk->used.count = index->used_count;
            trunk->used.bytes = index->used_bytes;
            trunk->free_start = index->free_start;
        } else {
            if ((result=set_trunk_by_space_log(ctx, trunk)) != 0) {
                return result;
            }
        }
        trunk->status = DA_TRUNK_STATUS_LOADED;

        /*
        logInfo("%s trunk id: %"PRId64", path index: %d, version: %"PRId64", "
                "calc: %d, used count: %u, used bytes: %"PRId64", "
                "free start: %u", ctx->module_name, trunk->id_info.id,
                trunk->allocator->path_info->store.index, version,
                index->version != version, trunk->used.count,
                trunk->used.bytes, trunk->free_start);
                */
    }

    da_trunk_hashtable_iterator(&ctx->trunk_htable_ctx, &it, false);
    while ((trunk=da_trunk_hashtable_next(&it)) != NULL) {
        if (trunk->status == DA_TRUNK_STATUS_NONE) {
            if ((result=set_trunk_by_space_log(ctx, trunk)) != 0) {
                return result;
            }

            /*
               logInfo("%s trunk id: %"PRId64", path index: %d, used_count: %u, "
               "used_bytes: %u, free_start: %u", ctx->module_name,
               trunk->id_info.id, trunk->allocator->path_info->store.index,
               trunk->used.count, trunk->used.bytes, trunk->free_start);
             */
        } else {
            trunk->status = DA_TRUNK_STATUS_NONE;
        }
    }

    return 0;
}

static void *trunk_space_log_func(void *arg)
{
    DAContext *ctx;
    DATrunkSpaceLogRecord *head;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "trunk-space-log");
#endif

    ctx = arg;
    while (SF_G_CONTINUE_FLAG) {
        if ((head=fc_queue_pop_all(&ctx->space_log_ctx.queue)) == NULL) {
            continue;
        }

        if (deal_all_records(ctx, head) != 0) {
            logCrit("file: "__FILE__", line: %d, %s "
                    "deal records fail, program exit!",
                    __LINE__, ctx->module_name);
            sf_terminate_myself();
            break;
        }

    }

    return NULL;
}


static int trunk_index_dump(void *args)
{
    if (dump_trunk_indexes(args) != 0) {
        logCrit("file: "__FILE__", line: %d, %s "
                "dump trunk index fail, program exit!", __LINE__,
                ((DAContext *)args)->module_name);
        sf_terminate_myself();
    }

    return 0;
}

int da_trunk_space_log_init(DAContext *ctx)
{
    const int alloc_skiplist_once = 256;
    const bool allocator_use_lock = true;
    int result;

    if ((result=da_space_log_reader_init(&ctx->space_log_ctx.reader, ctx,
                    alloc_skiplist_once, allocator_use_lock)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&ctx->space_log_ctx.queue, (long)
                    (&((DATrunkSpaceLogRecord *)NULL)->next))) != 0)
    {
        return result;
    }

    if ((result=sf_synchronize_ctx_init(&ctx->space_log_ctx.notify)) != 0) {
        return result;
    }

    if ((result=da_trunk_fd_cache_init(&FD_CACHE_CTX, ctx->storage.cfg.
                    fd_cache_capacity_per_write_thread)) != 0)
    {
        return result;
    }

    if ((result=fast_buffer_init_ex(&ctx->space_log_ctx.buffer,
                    ctx->data.binlog_buffer_size)) != 0)
    {
        return result;
    }

    RECORD_PTR_ARRAY.records = NULL;
    RECORD_PTR_ARRAY.count = 0;
    RECORD_PTR_ARRAY.alloc = 0;
    return 0;
}

int da_trunk_space_log_start(DAContext *ctx)
{
    ScheduleArray scheduleArray;
    ScheduleEntry scheduleEntries[1];
    pthread_t tid;
    int result;

    if ((result=load_trunk_indexes(ctx)) != 0) {
        return result;
    }

    INIT_SCHEDULE_ENTRY_EX(scheduleEntries[0], sched_generate_next_id(),
            ctx->data.trunk_index_dump_base_time,
            ctx->data.trunk_index_dump_interval,
            trunk_index_dump, ctx);
    scheduleArray.entries = scheduleEntries;
    scheduleArray.count = 1;
    if ((result=sched_add_entries(&scheduleArray)) != 0) {
        return result;
    }

    return fc_create_thread(&tid, trunk_space_log_func,
            ctx, SF_G_THREAD_STACK_SIZE);
}

void da_trunk_space_log_destroy(DAContext *ctx)
{
}
