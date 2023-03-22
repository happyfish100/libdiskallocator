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

#define SPACE_LOG_MAX_FIELD_COUNT        10

#define SPACE_LOG_FIELD_INDEX_TIMESTAMP   0
#define SPACE_LOG_FIELD_INDEX_VERSION     1
#define SPACE_LOG_FIELD_INDEX_INODE       2
#define SPACE_LOG_FIELD_INDEX_FINDEX      3
#define SPACE_LOG_FIELD_INDEX_OP_TYPE     4
#define SPACE_LOG_FIELD_INDEX_TRUNK_ID    5
#define SPACE_LOG_FIELD_INDEX_LENGTH      6
#define SPACE_LOG_FIELD_INDEX_OFFSET      7
#define SPACE_LOG_FIELD_INDEX_SIZE        8
#define SPACE_LOG_FIELD_INDEX_EXTRA       9

int da_trunk_space_log_unpack(const string_t *line,
        DATrunkSpaceLogRecord *record, char *error_info,
        const bool have_extra_field)
{
    int count;
    int expect;
    char size_endchr;
    char *endptr;
    string_t cols[SPACE_LOG_MAX_FIELD_COUNT];

    if (have_extra_field) {
        size_endchr = ' ';
        expect = SPACE_LOG_MAX_FIELD_COUNT;
    } else {
        size_endchr = '\n';
        expect = SPACE_LOG_MAX_FIELD_COUNT - 1;
    }
    count = split_string_ex(line, ' ', cols,
            SPACE_LOG_MAX_FIELD_COUNT, false);
    if (count != expect) {
        sprintf(error_info, "record count: %d != %d", count, expect);
        return EINVAL;
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

static int chain_to_array(DAContext *ctx, DATrunkSpaceLogRecord *head)
{
    int result;
    DATrunkSpaceLogRecord *record;

    RECORD_PTR_ARRAY.count = 0;
    record = head;
    do {
        if (RECORD_PTR_ARRAY.count == RECORD_PTR_ARRAY.alloc) {
            if ((result=realloc_record_array(&RECORD_PTR_ARRAY)) != 0) {
                return result;
            }
        }

        RECORD_PTR_ARRAY.records[RECORD_PTR_ARRAY.count++] = record;
    } while ((record=record->next) != NULL);

    ctx->trunk_index_ctx.last_version = RECORD_PTR_ARRAY.
        records[RECORD_PTR_ARRAY.count - 1]->storage.version;

    if (RECORD_PTR_ARRAY.count > 1) {
        qsort(RECORD_PTR_ARRAY.records, RECORD_PTR_ARRAY.count,
                sizeof(DATrunkSpaceLogRecord *),
                (int (*)(const void *, const void *))record_ptr_compare);
    }

    return 0;
}

int da_trunk_space_log_calc_version(DAContext *ctx,
        const uint32_t trunk_id, int64_t *version)
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

static int get_write_fd(DAContext *ctx, const uint32_t trunk_id, int *fd)
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

static int do_write_to_file(DAContext *ctx, const uint32_t trunk_id,
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

    if (flush && fsync(fd) != 0) {
        result = errno != 0 ? errno : EIO;
        dio_get_space_log_filename(ctx, trunk_id, space_log_filename,
                sizeof(space_log_filename));
        logError("file: "__FILE__", line: %d, %s "
                "fsync to space log file \"%s\" fail, "
                "errno: %d, error info: %s", __LINE__, ctx->module_name,
                space_log_filename, result, STRERROR(result));
        return result;
    }

    return 0;
}

static int write_to_log_file(DAContext *ctx,
        DATrunkSpaceLogRecord **start,
        DATrunkSpaceLogRecord **end)
{
    int result;
    int fd;
    uint32_t used_bytes;
    DATrunkSpaceLogRecord **current;

    if ((result=get_write_fd(ctx, (*start)->storage.trunk_id, &fd)) != 0) {
        return result;
    }

    used_bytes = 0;
    ctx->space_log_ctx.buffer.length = 0;
    do {
        for (current=start; current<end; current++) {
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

        if ((result=do_write_to_file(ctx, (*start)->storage.trunk_id,
                        fd, ctx->space_log_ctx.buffer.data,
                        ctx->space_log_ctx.buffer.length, true)) != 0)
        {
            break;
        }

        result = da_trunk_allocator_deal_space_changes(ctx,
                start, end - start, &used_bytes);
    } while (0);

    if (result != 0 || used_bytes == 0) {
        da_trunk_fd_cache_delete(&FD_CACHE_CTX, (*start)->storage.trunk_id);
    }
    return result;
}

int da_trunk_space_log_unlink(DAContext *ctx, const uint32_t trunk_id)
{
    char space_log_filename[PATH_MAX];

    dio_get_space_log_filename(ctx, trunk_id, space_log_filename,
            sizeof(space_log_filename));
    return fc_delete_file_ex(space_log_filename, "trunk space log");
}

static int array_to_log_file(DAContext *ctx,
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
        if ((*current)->storage.trunk_id != (*start)->storage.trunk_id) {
            if ((result=write_to_log_file(ctx, start, current)) != 0) {
                return result;
            }
            start = current;
        }
    }

    return write_to_log_file(ctx, start, current);
}

static int deal_records(DAContext *ctx, DATrunkSpaceLogRecord *head)
{
    int result;

    if ((result=chain_to_array(ctx, head)) != 0) {
        return result;
    }

    result = array_to_log_file(ctx, &RECORD_PTR_ARRAY);

    sf_synchronize_counter_notify(&ctx->space_log_ctx.notify,
            RECORD_PTR_ARRAY.count);

    fast_mblock_free_objects(&DA_SPACE_LOG_RECORD_ALLOCATOR(ctx),
            (void **)RECORD_PTR_ARRAY.records, RECORD_PTR_ARRAY.count);
    return result;
}

static int redo_by_trunk(DAContext *ctx, DATrunkSpaceLogRecord **start,
        DATrunkSpaceLogRecord **end, int *redo_count)
{
#define FIXED_RECORD_COUNT   1024
    const bool ignore_enoent = true;
    bool found;
    bool keep;
    int result;
    int count;
    DATrunkSpaceLogRecord *fixed[FIXED_RECORD_COUNT];
    DATrunkSpaceLogRecord **current;
    UniqSkiplist *skiplist;
    DATrunkSpaceLogRecord target;
    DATrunkSpaceLogRecordArray array;

    if ((result=da_space_log_reader_load_ex(&ctx->space_log_ctx.reader,
                    (*start)->storage.trunk_id, &skiplist, ignore_enoent)) != 0)
    {
        return result;
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
        if (skiplist != NULL) {
            target.storage.offset = (*current)->storage.offset;
            found = (uniq_skiplist_find(skiplist, &target) != NULL);
        } else {
            found = false;
        }
        if ((*current)->op_type == da_binlog_op_type_consume_space) {
            keep = !found;
        } else {  //da_binlog_op_type_reclaim_space
            keep = found;
        }

        if (keep) {
            array.records[array.count++] = *current;
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
    if (skiplist != NULL) {
        uniq_skiplist_free(skiplist);
    }

    return result;
}

static int redo_by_array(DAContext *ctx, DATrunkSpaceLogRecordArray *array)
{
    int result;
    int redo_count;
    DATrunkSpaceLogRecord **start;
    DATrunkSpaceLogRecord **end;
    DATrunkSpaceLogRecord **current;

    redo_count = 0;
    start = array->records;
    current = start;
    end = array->records + array->count;
    while (++current < end) {
        if ((*current)->storage.trunk_id != (*start)->storage.trunk_id) {
            if ((result=redo_by_trunk(ctx, start, current, &redo_count)) != 0) {
                return result;
            }
            start = current;
        }
    }

    if ((result=redo_by_trunk(ctx, start, current, &redo_count)) != 0) {
        return result;
    }

    return 0;
}

int da_trunk_space_log_redo_by_chain(DAContext *ctx,
        struct fc_queue_info *chain)
{
    int result;

    if (chain->head == NULL) {
        return 0;
    }

    if ((result=chain_to_array(ctx, chain->head)) != 0) {
        return result;
    }

    result = redo_by_array(ctx, &RECORD_PTR_ARRAY);
    fast_mblock_free_objects(&DA_SPACE_LOG_RECORD_ALLOCATOR(ctx),
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
    const bool ignore_enoent = true;
    int result;
    UniqSkiplist *skiplist;
    UniqSkiplistIterator it;
    DATrunkSpaceLogRecord *record;
    DATrunkSpaceLogRecord *last;

    if ((result=da_space_log_reader_load_ex(&ctx->space_log_ctx.reader,
                    trunk->id_info.id, &skiplist, ignore_enoent)) != 0)
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
    DATrunkFileInfo *trunk;
    DATrunkIndexRecord *index;
    DATrunkIndexRecord *end;
    DATrunkHashtableIterator it;

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
                "calc: %d, used count: %u, used bytes: %u, "
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
            trunk->status = DA_TRUNK_STATUS_LOADED;

            /*
            logInfo("%s trunk id: %"PRId64", path index: %d, used_count: %u, "
                    "used_bytes: %u, free_start: %u", ctx->module_name,
                    trunk->id_info.id, trunk->allocator->path_info->store.index,
                    trunk->used.count, trunk->used.bytes, trunk->free_start);
                    */
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

        if (deal_records(ctx, head) != 0) {
            logCrit("file: "__FILE__", line: %d, %s "
                    "deal records fail, program exit!",
                    __LINE__, ctx->module_name);
            sf_terminate_myself();
            break;
        }

    }

    return NULL;
}


static int binlog_index_dump(void *args)
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
            binlog_index_dump, ctx);
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
