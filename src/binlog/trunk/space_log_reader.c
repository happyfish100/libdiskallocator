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
#include "../../global.h"
#include "../../storage_allocator.h"
#include "../../dio/trunk_fd_cache.h"
#include "trunk_space_log.h"
#include "space_log_reader.h"

#define DA_SPACE_SKPLIST_INIT_LEVEL_COUNT  4
#define DA_SPACE_SKPLIST_MAX_LEVEL_COUNT  12

static int compare_by_trunk_offset(const DATrunkSpaceLogRecord *s1,
        const DATrunkSpaceLogRecord *s2)
{
    return fc_compare_int64(s1->storage.offset, s2->storage.offset);
}

static void space_log_record_free_func(void *ptr, const int delay_seconds)
{
    fast_mblock_free_object(((DATrunkSpaceLogRecord *)ptr)->allocator, ptr);
}

static int space_log_record_alloc_init(void *element, void *args)
{
    ((DATrunkSpaceLogRecord *)element)->allocator =
        (struct fast_mblock_man *)args;
    return 0;
}

int da_space_log_reader_init(DASpaceLogReader *reader, DAContext *ctx,
        const int alloc_skiplist_once, const bool use_lock)
{
    const int min_alloc_elements_once = 4;
    const int delay_free_seconds = 0;
    const bool bidirection = false;
    int result;

    reader->ctx = ctx;
    reader->current_version = 0;
    if ((result=fast_mblock_init_ex1(&reader->record_allocator,
                    "space-log-record", sizeof(DATrunkSpaceLogRecord),
                    8 * 1024, 0, space_log_record_alloc_init,
                    &reader->record_allocator, true)) != 0)
    {
        return result;
    }

    if ((result=uniq_skiplist_init_ex2(&reader->factory,
                    DA_SPACE_SKPLIST_MAX_LEVEL_COUNT, (skiplist_compare_func)
                    compare_by_trunk_offset, space_log_record_free_func,
                    alloc_skiplist_once, min_alloc_elements_once,
                    delay_free_seconds, bidirection, use_lock)) != 0)
    {
        return result;
    }

    return 0;
}

void da_space_log_reader_destroy(DASpaceLogReader *reader)
{
    fast_mblock_destroy(&reader->record_allocator);
    uniq_skiplist_destroy(&reader->factory);
}

static int parse_to_skiplist(DASpaceLogReader *reader,
        UniqSkiplist *skiplist, string_t *content, char *error_info)
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

        record = da_trunk_space_log_alloc_record1(reader);
        if (record == NULL) {
            sprintf(error_info, "alloc record object fail "
                    "because out of memory");
            return ENOMEM;
        }

        ++line_end;
        line.str = line_start;
        line.len = line_end - line_start;
        if ((result=da_trunk_space_log_unpack(&line, record, error_info,
                        reader->ctx->storage.have_extra_field)) != 0)
        {
            return result;
        }

        if (record->op_type == da_binlog_op_type_consume_space) {
            result = uniq_skiplist_insert(skiplist, record);
            need_free = (result != 0);
        } else {
            result = uniq_skiplist_delete(skiplist, record);
            need_free = true;
        }

        if (need_free) {
            fast_mblock_free_object(record->allocator, record);
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

int da_space_log_reader_load(DASpaceLogReader *reader,
        const uint64_t trunk_id, UniqSkiplist **skiplist)
{
    int result;
    int fd;
    string_t content;
    char space_log_filename[PATH_MAX];
    char buff[64 * 1024];
    char error_info[256];

    *skiplist = uniq_skiplist_new(&reader->factory,
            DA_SPACE_SKPLIST_INIT_LEVEL_COUNT);
    if (*skiplist == NULL) {
        return ENOMEM;
    }

    dio_get_space_log_filename(reader->ctx, trunk_id,
            space_log_filename, sizeof(space_log_filename));
    if ((fd=open(space_log_filename, O_RDONLY | O_CLOEXEC)) < 0) {
        result = errno != 0 ? errno : EACCES;
        if (result == ENOENT) {
            return 0;
        } else {
            logError("file: "__FILE__", line: %d, %s "
                    "open file \"%s\" fail, errno: %d, error info: %s",
                    __LINE__, reader->ctx->module_name, space_log_filename,
                    result, STRERROR(result));
            uniq_skiplist_free(*skiplist);
            *skiplist = NULL;
            return result;
        }
    }

    result = 0;
    *error_info = '\0';
    content.str = buff;
    while ((content.len=fc_read_lines(fd, buff, sizeof(buff))) > 0) {
        if ((result=parse_to_skiplist(reader, *skiplist,
                        &content, error_info)) != 0)
        {
            logError("file: "__FILE__", line: %d, %s "
                    "parse file: %s fail, errno: %d, error info: %s",
                    __LINE__, reader->ctx->module_name, space_log_filename,
                    result, error_info);
            break;
        }
    }

    if (content.len < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "read from file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, reader->ctx->module_name, space_log_filename,
                result, STRERROR(result));
    }
    close(fd);

    if (result != 0) {
        uniq_skiplist_free(*skiplist);
        *skiplist = NULL;
    }

    return result;
}

static int parse_to_chain(DASpaceLogReader *reader,
        struct fc_queue_info *chain, string_t *content,
        char *error_info)
{
    int result;
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

        record = da_trunk_space_log_alloc_record1(reader);
        if (record == NULL) {
            sprintf(error_info, "alloc record object fail "
                    "because out of memory");
            return ENOMEM;
        }

        ++line_end;
        line.str = line_start;
        line.len = line_end - line_start;
        if ((result=da_trunk_space_log_unpack(&line, record, error_info,
                        reader->ctx->storage.have_extra_field)) != 0)
        {
            return result;
        }

        if (chain->head == NULL) {
            chain->head = record;
        } else {
            FC_SET_CHAIN_TAIL_NEXT(*chain, DATrunkSpaceLogRecord, record);
        }
        chain->tail = record;

        line_start = line_end;
    }

    return 0;
}

int da_space_log_reader_load_to_chain(DASpaceLogReader *reader,
        const char *space_log_filename, struct fc_queue_info *chain)
{
    int result;
    int fd;
    string_t content;
    char buff[64 * 1024];
    char error_info[256];

    chain->head = chain->tail = NULL;
    if ((fd=open(space_log_filename, O_RDONLY | O_CLOEXEC)) < 0) {
        result = errno != 0 ? errno : EACCES;
        if (result == ENOENT) {
            return 0;
        }

        logError("file: "__FILE__", line: %d, %s "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, reader->ctx->module_name, space_log_filename,
                result, STRERROR(result));
        return result;
    }

    result = 0;
    *error_info = '\0';
    content.str = buff;
    while ((content.len=fc_read_lines(fd, buff, sizeof(buff))) > 0) {
        if ((result=parse_to_chain(reader, chain,
                        &content, error_info)) != 0)
        {
            logError("file: "__FILE__", line: %d, %s "
                    "parse file: %s fail, errno: %d, error info: %s",
                    __LINE__, reader->ctx->module_name, space_log_filename,
                    result, error_info);
            break;
        }
    }

    if (content.len < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "read from file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, reader->ctx->module_name, space_log_filename,
                result, STRERROR(result));
    }
    close(fd);

    if (chain->tail != NULL) {
        FC_SET_CHAIN_TAIL_NEXT(*chain, DATrunkSpaceLogRecord, NULL);
    }

    return result;
}
