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
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "../../global.h"
#include "../../dio/trunk_write_thread.h"
#include "../../storage_allocator.h"
#include "../../trunk/trunk_id_info.h"
#include "trunk_binlog.h"

#define MAX_FIELD_COUNT         8
#define EXPECT_FIELD_COUNT      6

#define FIELD_INDEX_TIMESTAMP   0
#define FIELD_INDEX_OP_TYPE     1
#define FIELD_INDEX_PATH_INDEX  2
#define FIELD_INDEX_TRUNK_ID    3
#define FIELD_INDEX_SUBDIR      4
#define FIELD_INDEX_TRUNK_SIZE  5

static int trunk_parse_line(DAContext *ctx,
        const string_t *line, char *error_info)
{
    int result;
    int count;
    string_t cols[MAX_FIELD_COUNT];
    char *endptr;
    char op_type;
    int path_index;
    DATrunkIdInfo id_info;
    uint32_t trunk_size;

    count = split_string_ex(line, ' ', cols, MAX_FIELD_COUNT, false);
    if (count < EXPECT_FIELD_COUNT) {
        sprintf(error_info, "field count: %d < %d",
                count, EXPECT_FIELD_COUNT);
        return EINVAL;
    }

    op_type = cols[FIELD_INDEX_OP_TYPE].str[0];
    SF_BINLOG_PARSE_INT_SILENCE(path_index, "path index",
            FIELD_INDEX_PATH_INDEX, ' ', 0);
    if (path_index > ctx->storage.cfg.max_store_path_index) {
        sprintf(error_info, "invalid path_index: %d > "
                "max_store_path_index: %d", path_index,
                ctx->storage.cfg.max_store_path_index);
        return EINVAL;
    }

    SF_BINLOG_PARSE_INT_SILENCE(id_info.id, "trunk id",
            FIELD_INDEX_TRUNK_ID, ' ', 1);
    SF_BINLOG_PARSE_INT_SILENCE(id_info.subdir, "subdir",
            FIELD_INDEX_SUBDIR, ' ', 1);
    SF_BINLOG_PARSE_INT_SILENCE(trunk_size, "trunk size",
            FIELD_INDEX_TRUNK_SIZE, '\n', DA_TRUNK_FILE_MIN_SIZE);
    if (trunk_size > DA_TRUNK_FILE_MAX_SIZE) {
        sprintf(error_info, "invalid trunk size: %u", trunk_size);
        return EINVAL;
    }

    if (path_index == ctx->storage.skip_path_index) {
        return 0;
    }

    if (op_type == DA_IO_TYPE_CREATE_TRUNK) {
        if ((result=da_storage_allocator_add_trunk(ctx, path_index,
                       &id_info, trunk_size)) != 0)
        {
            sprintf(error_info, "add trunk fail, errno: %d, "
                    "error info: %s", result, STRERROR(result));
        }
    } else if (op_type == DA_IO_TYPE_DELETE_TRUNK) {
        if ((result=da_storage_allocator_delete_trunk(ctx, path_index,
                        &id_info)) != 0)
        {
            sprintf(error_info, "delete trunk fail, errno: %d, "
                    "error info: %s", result, STRERROR(result));
        }
    } else {
        sprintf(error_info, "invalid op_type: %c (0x%02x)",
                op_type, (unsigned char)op_type);
        result = EINVAL;
    }

    return result;
}

static int trunk_parse_content(DAContext *ctx, string_t *content,
        int *line_count, char *error_info)
{
    int result;
    string_t line;
    char *line_start;
    char *buff_end;
    char *line_end;

    result = 0;
    line_start = content->str;
    buff_end = content->str + content->len;
    while (line_start < buff_end) {
        line_end = (char *)memchr(line_start, '\n', buff_end - line_start);
        if (line_end == NULL) {
            break;
        }

        ++(*line_count);
        ++line_end;
        line.str = line_start;
        line.len = line_end - line_start;
        if ((result=trunk_parse_line(ctx, &line, error_info)) != 0) {
            return result;
        }

        line_start = line_end;
    }

    return 0;
}

static int load_one_binlog(DAContext *ctx, const int binlog_index)
{
    int result;
    int fd;
    int line_count;
    string_t content;
    char full_filename[PATH_MAX];
    char buff[64 * 1024];
    char error_info[256];

    sf_binlog_writer_get_filename(ctx->data.path.str,
            DA_TRUNK_BINLOG_SUBDIR_NAME, binlog_index,
            full_filename, sizeof(full_filename));
    if ((fd=open(full_filename, O_RDONLY | O_CLOEXEC)) < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, ctx->module_name, full_filename,
                result, STRERROR(result));
        return result;
    }

    line_count = 0;
    result = 0;
    *error_info = '\0';
    content.str = buff;
    while ((content.len=fc_read_lines(fd, buff, sizeof(buff))) > 0) {
        if ((result=trunk_parse_content(ctx, &content,
                        &line_count, error_info)) != 0)
        {
            logError("file: "__FILE__", line: %d, %s "
                    "parse file: %s fail, line no: %d, errno: %d, "
                    "error info: %s", __LINE__, ctx->module_name,
                    full_filename, line_count, result, error_info);
            break;
        }
    }

    if (content.len < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "read from file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, ctx->module_name, full_filename,
                result, STRERROR(result));
    }
    close(fd);

    return result;
}

static int trunk_binlog_load(DAContext *ctx)
{
    int result;
    int binlog_index;
    int current_index;

    current_index = sf_binlog_get_current_write_index(
            &ctx->trunk_binlog_writer.writer);
    for (binlog_index=0; binlog_index<=current_index; binlog_index++) {
        if ((result=load_one_binlog(ctx, binlog_index)) != 0) {
            return result;
        }
    }

    return 0;
}

int da_trunk_binlog_init(DAContext *ctx)
{
    const int write_interval_ms = 0;
    const int max_delay = 1;
    int result;

    if ((result=sf_binlog_writer_init(&ctx->trunk_binlog_writer,
                    ctx->data.path.str, DA_TRUNK_BINLOG_SUBDIR_NAME,
                    ctx->data.binlog_buffer_size, write_interval_ms,
                    max_delay, DA_TRUNK_BINLOG_MAX_RECORD_SIZE)) != 0)
    {
        return result;
    }

    return trunk_binlog_load(ctx);
}

void da_trunk_binlog_destroy(DAContext *ctx)
{
    sf_binlog_writer_finish(&ctx->trunk_binlog_writer.writer);
}

int da_trunk_binlog_write(DAContext *ctx, const char op_type,
        const int path_index, const DATrunkIdInfo *id_info,
        const uint32_t file_size)
{
    SFBinlogWriterBuffer *wbuffer;

    if ((wbuffer=sf_binlog_writer_alloc_buffer(&ctx->
                    trunk_binlog_writer.thread)) == NULL)
    {
        return ENOMEM;
    }

    wbuffer->bf.length = da_trunk_binlog_log_to_buff(op_type,
            path_index, id_info, file_size, wbuffer->bf.buff);
    sf_push_to_binlog_write_queue(&ctx->trunk_binlog_writer.writer, wbuffer);
    return 0;
}

static int get_last_id_info(DAContext *ctx,
        DATrunkIdInfo *id_info, char *error_info)
{
    int result;
    int count;
    int current_write_index;
    char op_type;
    int path_index;
    char buff[DA_TRUNK_BINLOG_MAX_RECORD_SIZE];
    string_t cols[MAX_FIELD_COUNT];
    string_t line;
    char *endptr;

    current_write_index = da_trunk_binlog_get_current_write_index(ctx);
    line.str = buff;
    count = 1;
    if ((result=sf_binlog_writer_get_last_lines(ctx->data.path.str,
                    DA_TRUNK_BINLOG_SUBDIR_NAME, current_write_index,
                    buff, sizeof(buff), &count, &line.len)) != 0)
    {
        return result;
    }

    if (count == 0) {
        id_info->id = 0;
        id_info->subdir = 0;
        return 0;
    }

    count = split_string_ex(&line, ' ', cols, MAX_FIELD_COUNT, false);
    if (count < EXPECT_FIELD_COUNT) {
        logError("file: "__FILE__", line: %d, %s "
                "field count: %d < %d", __LINE__, ctx->module_name,
                count, EXPECT_FIELD_COUNT);
        return EINVAL;
    }

    op_type = cols[FIELD_INDEX_OP_TYPE].str[0];
    if (op_type != DA_IO_TYPE_CREATE_TRUNK) {
        logError("file: "__FILE__", line: %d, %s "
                "invalid op_type: 0x%02x", __LINE__,
                ctx->module_name, op_type);
        return EINVAL;
    }

    SF_BINLOG_PARSE_INT_SILENCE(path_index, "path index",
            FIELD_INDEX_PATH_INDEX, ' ', 0);
    if (path_index > ctx->storage.cfg.max_store_path_index) {
        logError("file: "__FILE__", line: %d, %s "
                "invalid path_index: %d > max_store_path_index: %d",
                __LINE__, ctx->module_name, path_index,
                ctx->storage.cfg.max_store_path_index);
        return EINVAL;
    }

    SF_BINLOG_PARSE_INT_SILENCE(id_info->id, "trunk id",
            FIELD_INDEX_TRUNK_ID, ' ', 1);
    SF_BINLOG_PARSE_INT_SILENCE(id_info->subdir, "subdir",
            FIELD_INDEX_SUBDIR, ' ', 1);
    return 0;
}

int da_trunk_binlog_get_last_id_info(DAContext *ctx,
        DATrunkIdInfo *id_info)
{
    int result;
    char error_info[256];

    *error_info = '\0';
    if ((result=get_last_id_info(ctx, id_info, error_info)) != 0) {
        if (*error_info != '\0') {
            logError("file: "__FILE__", line: %d, %s "
                    "parse last line of trunk binlog fail, error info: %s",
                    __LINE__, ctx->module_name, error_info);
        }
    }

    return result;
}
