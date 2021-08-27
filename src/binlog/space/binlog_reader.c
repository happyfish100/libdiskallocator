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

#include "fastcommon/logger.h"
#include "fastcommon/shared_func.h"
#include "../common/binlog_fd_cache.h"
#include "binlog_reader.h"

static int load(const DABinlogIdTypePair *bkey,
        void *args, const string_t *context)
{
    int result;
    string_t line;
    char *line_start;
    char *buff_end;
    char *line_end;
    char error_info[256];

    result = 0;
    line_start = context->str;
    buff_end = context->str + context->len;
    while (line_start < buff_end) {
        line_end = (char *)memchr(line_start, '\n', buff_end - line_start);
        if (line_end == NULL) {
            break;
        }

        ++line_end;
        line.str = line_start;
        line.len = line_end - line_start;
        if ((result=g_da_write_cache_ctx.type_subdir_array.pairs[bkey->type].
                    unpack_record(&line, args, error_info)) != 0)
        {
            char filename[PATH_MAX];
            da_write_fd_cache_filename(bkey, filename, sizeof(filename));
            logError("file: "__FILE__", line: %d, "
                    "parse record fail, binlog id: %"PRId64", "
                    "binlog file: %s%s%s", __LINE__, bkey->id, filename,
                    (*error_info != '\0' ? ", error info: " : ""), error_info);
            break;
        }

        line_start = line_end;
    }

    return result;
}

int da_binlog_reader_load(const DABinlogIdTypePair *bkey, void *args)
{
    int result;
    char filename[PATH_MAX];
    int64_t file_size;
    string_t context;

    da_write_fd_cache_filename(bkey, filename, sizeof(filename));
    if (access(filename, F_OK) != 0) {
        result = errno != 0 ? errno : EPERM;
        if (result == ENOENT) {
            return 0;
        } else {
            logError("file: "__FILE__", line: %d, "
                    "binlog id: %"PRId64", access binlog file %s fail, "
                    "errno: %d, error info: %s", __LINE__, bkey->id,
                    filename, result,STRERROR(result));
            return result;
        }
    }

    if ((result=getFileContent(filename, &context.str, &file_size)) != 0) {
        return result;
    }
    context.len = file_size;

    result = load(bkey, args, &context);
    free(context.str);
    return result;
}
