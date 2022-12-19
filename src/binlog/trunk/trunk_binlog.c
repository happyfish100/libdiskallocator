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
#include "sf/sf_binlog_writer.h"
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

static SFBinlogWriterContext binlog_writer;

static int trunk_parse_line(const string_t *line, char *error_info)
{
    int result;
    int count;
    string_t cols[MAX_FIELD_COUNT];
    char *endptr;
    char op_type;
    int path_index;
    DATrunkIdInfo id_info;
    uint32_t trunk_size;

    count = split_string_ex(line, ' ', cols,
            MAX_FIELD_COUNT, false);
    if (count < EXPECT_FIELD_COUNT) {
        sprintf(error_info, "field count: %d < %d",
                count, EXPECT_FIELD_COUNT);
        return EINVAL;
    }

    op_type = cols[FIELD_INDEX_OP_TYPE].str[0];
    SF_BINLOG_PARSE_INT_SILENCE(path_index, "path index",
            FIELD_INDEX_PATH_INDEX, ' ', 0);
    if (path_index > DA_STORE_CFG.max_store_path_index) {
        sprintf(error_info, "invalid path_index: %d > "
                "max_store_path_index: %d", path_index,
                DA_STORE_CFG.max_store_path_index);
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

    if (op_type == DA_IO_TYPE_CREATE_TRUNK) {
        if ((result=da_storage_allocator_add_trunk(path_index,
                       &id_info, trunk_size)) != 0)
        {
            sprintf(error_info, "add trunk fail, errno: %d, "
                    "error info: %s", result, STRERROR(result));
        }
    } else if (op_type == DA_IO_TYPE_DELETE_TRUNK) {
        if ((result=da_storage_allocator_delete_trunk(path_index,
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

static int trunk_parse_content(string_t *content,
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
        if ((result=trunk_parse_line(&line, error_info)) != 0) {
            return result;
        }

        line_start = line_end;
    }

    return 0;
}

static int load_one_binlog(const int binlog_index)
{
    int result;
    int fd;
    int line_count;
    string_t content;
    char full_filename[PATH_MAX];
    char buff[64 * 1024];
    char error_info[256];

    sf_binlog_writer_get_filename(DA_DATA_PATH_STR,
            DA_TRUNK_BINLOG_SUBDIR_NAME, binlog_index,
            full_filename, sizeof(full_filename));

    if ((fd=open(full_filename, O_RDONLY | O_CLOEXEC)) < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, full_filename, result, STRERROR(result));
        return result;
    }

    line_count = 0;
    result = 0;
    *error_info = '\0';
    content.str = buff;
    while ((content.len=fc_read_lines(fd, buff, sizeof(buff))) > 0) {
        if ((result=trunk_parse_content(&content, &line_count,
                        error_info)) != 0)
        {
            logError("file: "__FILE__", line: %d, "
                    "parse file: %s fail, line no: %d, "
                    "errno: %d, error info: %s", __LINE__,
                    full_filename, line_count, result, error_info);
            break;
        }
    }

    if (content.len < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "read from file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, full_filename, result, STRERROR(result));
    }
    close(fd);

    return result;
}

static int da_trunk_binlog_load()
{
    int result;
    int binlog_index;
    int current_index;

    current_index = sf_binlog_get_current_write_index(&binlog_writer.writer);
    for (binlog_index=0; binlog_index<=current_index; binlog_index++) {
        if ((result=load_one_binlog(binlog_index)) != 0) {
            return result;
        }
    }

    return 0;
}

int da_trunk_binlog_get_current_write_index()
{
    return sf_binlog_get_current_write_index(&binlog_writer.writer);
}

static int init_binlog_writer()
{
    return sf_binlog_writer_init(&binlog_writer, DA_DATA_PATH_STR,
            DA_TRUNK_BINLOG_SUBDIR_NAME, DA_BINLOG_BUFFER_SIZE,
            DA_TRUNK_BINLOG_MAX_RECORD_SIZE);
}

int da_trunk_binlog_init()
{
    int result;
    if ((result=init_binlog_writer()) != 0) {
        return result;
    }

    return da_trunk_binlog_load();
}

void da_trunk_binlog_destroy()
{
    sf_binlog_writer_finish(&binlog_writer.writer);
}

int da_trunk_binlog_write(const char op_type, const int path_index,
        const DATrunkIdInfo *id_info, const uint32_t file_size)
{
    SFBinlogWriterBuffer *wbuffer;

    if ((wbuffer=sf_binlog_writer_alloc_buffer(&binlog_writer.thread)) == NULL) {
        return ENOMEM;
    }

    wbuffer->bf.length = sprintf(wbuffer->bf.buff, "%d %c %d %u %u %u\n",
            (int)g_current_time, op_type, path_index, id_info->id,
            id_info->subdir, file_size);
    sf_push_to_binlog_thread_queue(&binlog_writer.thread, wbuffer);
    return 0;
}
