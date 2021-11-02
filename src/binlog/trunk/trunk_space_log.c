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

DATrunkSpaceLogContext g_trunk_space_log_ctx;

#define RECORD_PTR_ARRAY  g_trunk_space_log_ctx.record_array
#define FD_CACHE_CTX      g_trunk_space_log_ctx.fd_cache_ctx
#define NEXT_DUMP_TIME    g_trunk_space_log_ctx.next_dump_time

#define SPACE_LOG_FIELD_COUNT             9

#define SPACE_LOG_FIELD_INDEX_TIMESTAMP   0
#define SPACE_LOG_FIELD_INDEX_VERSION     1
#define SPACE_LOG_FIELD_INDEX_INODE       2
#define SPACE_LOG_FIELD_INDEX_OP_TYPE     3
#define SPACE_LOG_FIELD_INDEX_FINDEX      4
#define SPACE_LOG_FIELD_INDEX_TRUNK_ID    5
#define SPACE_LOG_FIELD_INDEX_LENGTH      6
#define SPACE_LOG_FIELD_INDEX_OFFSET      7
#define SPACE_LOG_FIELD_INDEX_SIZE        8

int da_trunk_space_log_unpack(const string_t *line,
        DATrunkSpaceLogRecord *record, char *error_info)
{
    int count;
    char *endptr;
    string_t cols[SPACE_LOG_FIELD_COUNT];

    count = split_string_ex(line, ' ', cols,
            SPACE_LOG_FIELD_COUNT, false);
    if (count != SPACE_LOG_FIELD_COUNT) {
        sprintf(error_info, "record count: %d != %d",
                count, SPACE_LOG_FIELD_COUNT);
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
            SPACE_LOG_FIELD_INDEX_SIZE, '\n', 0);
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

    return fc_compare_int64((*record1)->storage.version,
            (*record2)->storage.version);
}

static int chain_to_array(DATrunkSpaceLogRecord *head)
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

    g_trunk_index_ctx.last_version = RECORD_PTR_ARRAY.
        records[RECORD_PTR_ARRAY.count - 1]->storage.version;

    if (RECORD_PTR_ARRAY.count > 1) {
        qsort(RECORD_PTR_ARRAY.records,
                RECORD_PTR_ARRAY.count,
                sizeof(DATrunkSpaceLogRecord *),
                (int (*)(const void *, const void *))
                record_ptr_compare);
    }

    return 0;
}

static int get_write_fd(const uint32_t trunk_id, int *fd)
{
    const int flags = O_WRONLY | O_CREAT | O_APPEND;
    int result;
    char space_log_filename[PATH_MAX];

    if ((*fd=trunk_fd_cache_get(&FD_CACHE_CTX, trunk_id)) >= 0) {
        return 0;
    }

    dio_get_space_log_filename(trunk_id, space_log_filename,
            sizeof(space_log_filename));
    if ((*fd=open(space_log_filename, flags, 0644)) < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, space_log_filename, result, STRERROR(result));
        return result;
    }

    trunk_fd_cache_add(&FD_CACHE_CTX, trunk_id, *fd);
    return 0;
}

static int do_write_to_file(const uint32_t trunk_id, int fd,
        char *buff, const int len, const bool flush)
{
    int result;
    char space_log_filename[PATH_MAX];

    if (fc_safe_write(fd, buff, len) != len) {
        result = errno != 0 ? errno : EIO;
        dio_get_space_log_filename(trunk_id, space_log_filename,
                sizeof(space_log_filename));
        logError("file: "__FILE__", line: %d, "
                "write to space log file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, space_log_filename,
                result, STRERROR(result));
        return result;
    }

    if (flush && fsync(fd) != 0) {
        result = errno != 0 ? errno : EIO;
        dio_get_space_log_filename(trunk_id, space_log_filename,
                sizeof(space_log_filename));
        logError("file: "__FILE__", line: %d, "
                "fsync to space log file \"%s\" fail, "
                "errno: %d, error info: %s",
                __LINE__, space_log_filename,
                result, STRERROR(result));
        return result;
    }

    return 0;
}

static int write_to_log_file(DATrunkSpaceLogRecord **start,
        DATrunkSpaceLogRecord **end)
{
    int result;
    int fd;
    DATrunkSpaceLogRecord **current;

    if ((result=get_write_fd((*start)->storage.trunk_id, &fd)) != 0) {
        return result;
    }

    g_trunk_space_log_ctx.buffer.length = 0;
    do {
        for (current=start; current<end; current++) {
            if (g_trunk_space_log_ctx.buffer.alloc_size -
                    g_trunk_space_log_ctx.buffer.length < 128)
            {
                if ((result=do_write_to_file((*start)->storage.trunk_id,
                                fd, g_trunk_space_log_ctx.buffer.data,
                                g_trunk_space_log_ctx.buffer.length,
                                false)) != 0)
                {
                    break;
                }

                g_trunk_space_log_ctx.buffer.length = 0;
            }

            da_trunk_space_log_pack(*current, &g_trunk_space_log_ctx.buffer);
        }

        result = do_write_to_file((*start)->storage.trunk_id,
                fd, g_trunk_space_log_ctx.buffer.data,
                g_trunk_space_log_ctx.buffer.length, true);
    } while (0);

    if (result != 0) {
        trunk_fd_cache_delete(&FD_CACHE_CTX, (*start)->storage.trunk_id);
    }
    return result;
}

static int array_to_log_file(DATrunkSpaceLogRecordArray *array)
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
            if ((result=write_to_log_file(start, current)) != 0) {
                return result;
            }
            start = current;
        }
    }

    return write_to_log_file(start, current);
}

static int deal_records(DATrunkSpaceLogRecord *head)
{
    int result;

    if ((result=chain_to_array(head)) != 0) {
        return result;
    }

    result = array_to_log_file(&RECORD_PTR_ARRAY);

    if (FC_ATOMIC_DEC_EX(g_trunk_space_log_ctx.notify.waiting_count,
                RECORD_PTR_ARRAY.count) == 0)
    {
        pthread_cond_signal(&g_trunk_space_log_ctx.notify.lcp.cond);
    }

    fast_mblock_free_objects(&DA_SPACE_LOG_RECORD_ALLOCATOR,
            (void **)RECORD_PTR_ARRAY.records, RECORD_PTR_ARRAY.count);
    return result;
}

static int redo_by_trunk(DATrunkSpaceLogRecord **start,
        DATrunkSpaceLogRecord **end)
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

    if ((result=da_space_log_reader_load_ex(&g_trunk_space_log_ctx.
                    reader, (*start)->storage.trunk_id,
                    &skiplist, ignore_enoent)) != 0)
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
        result = write_to_log_file(array.records,
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

static int redo_by_array(DATrunkSpaceLogRecordArray *array)
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
            if ((result=redo_by_trunk(start, current)) != 0) {
                return result;
            }
            start = current;
        }
    }

    return redo_by_trunk(start, current);
}

int da_trunk_space_log_redo(struct fc_queue_info *qinfo)
{
    int result;

    if ((result=chain_to_array(qinfo->head)) != 0) {
        return result;
    }

    result = redo_by_array(&RECORD_PTR_ARRAY);

    fast_mblock_free_objects(&DA_SPACE_LOG_RECORD_ALLOCATOR,
            (void **)RECORD_PTR_ARRAY.records, RECORD_PTR_ARRAY.count);
    return result;
}

static int dump_trunk_indexes()
{
    int result;
    if ((result=storage_allocator_trunks_to_array(
                    &g_trunk_index_ctx.index_array)) != 0)
    {
        return result;
    }

    return trunk_index_save();
}

static void *trunk_space_log_func(void *arg)
{
    DATrunkSpaceLogRecord *head;

#ifdef OS_LINUX
    prctl(PR_SET_NAME, "trunk-space-log");
#endif

    while (SF_G_CONTINUE_FLAG) {
        if ((head=fc_queue_pop_all(&g_trunk_space_log_ctx.queue)) == NULL) {
            continue;
        }

        if (deal_records(head) != 0) {
            logCrit("file: "__FILE__", line: %d, "
                    "deal records fail, program exit!",
                    __LINE__);
            sf_terminate_myself();
            break;
        }

        if (g_current_time > NEXT_DUMP_TIME) {
            if (dump_trunk_indexes() != 0) {
                logCrit("file: "__FILE__", line: %d, "
                        "dump trunk index fail, program exit!",
                        __LINE__);
                sf_terminate_myself();
                break;
            }
            NEXT_DUMP_TIME += DA_TRUNK_INDEX_DUMP_INTERVAL;
        }
    }

    return NULL;
}

int da_trunk_space_log_init()
{
    const int alloc_skiplist_once = 256;
    const bool allocator_use_lock = true;
    int result;
    struct tm tm_current;
    pthread_t tid;

    if ((result=da_space_log_reader_init(&g_trunk_space_log_ctx.reader,
                    alloc_skiplist_once, allocator_use_lock)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&g_trunk_space_log_ctx.queue, (long)
                    (&((DATrunkSpaceLogRecord *)NULL)->next))) != 0)
    {
        return result;
    }

    if ((result=sf_synchronize_ctx_init(&g_trunk_space_log_ctx.notify)) != 0) {
        return result;
    }

    if ((result=trunk_fd_cache_init(&FD_CACHE_CTX, DA_STORE_CFG.
                    fd_cache_capacity_per_write_thread)) != 0)
    {
        return result;
    }

    if ((result=fast_buffer_init_ex(&g_trunk_space_log_ctx.buffer,
                    DA_BINLOG_BUFFER_SIZE)) != 0)
    {
        return result;
    }

    g_current_time = time(NULL);
    localtime_r((time_t *)&g_current_time, &tm_current);
    NEXT_DUMP_TIME = sched_make_first_call_time(&tm_current,
            &DA_TRUNK_INDEX_DUMP_BASE_TIME, DA_TRUNK_INDEX_DUMP_INTERVAL);

    return fc_create_thread(&tid, trunk_space_log_func,
            NULL, SF_G_THREAD_STACK_SIZE);
}

void da_trunk_space_log_destroy()
{
}
