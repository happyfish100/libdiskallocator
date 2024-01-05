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

static int parse_buffer(const char *filename, const BufferInfo *buffer,
        int *line_count, da_binlog_unpack_record_func unpack_func,
        void *args)
{
    int result;
    string_t line;
    char *line_start;
    char *buff_end;
    char *line_end;
    char error_info[256];

    result = 0;
    *error_info = '\0';
    line_start = buffer->buff;
    buff_end = buffer->buff + buffer->length;
    while (line_start < buff_end) {
        line_end = (char *)memchr(line_start, '\n', buff_end - line_start);
        if (line_end == NULL) {
            break;
        }

        ++(*line_count);
        ++line_end;
        line.str = line_start;
        line.len = line_end - line_start;
        if ((result=unpack_func(&line, args, error_info)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "parse record fail, binlog file: %s, line "
                    "no: %d%s%s", __LINE__, filename, *line_count,
                    (*error_info != '\0' ? ", error info: " : ""), error_info);
            break;
        }

        line_start = line_end;
    }

    return result;
}

int da_binlog_reader_load_ex(const char *filename,
        da_binlog_unpack_record_func unpack_func, void *args)
{
    int result;
    int fd;
    int line_count;
    struct stat stbuf;
    BufferInfo buffer;

    if (stat(filename, &stbuf) != 0) {
        result = errno != 0 ? errno : EPERM;
        if (result == ENOENT) {
            return 0;
        } else {
            logError("file: "__FILE__", line: %d, "
                    "stat binlog file %s fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
            return result;
        }
    }

    if (!S_ISREG(stbuf.st_mode)) {
        logError("file: "__FILE__", line: %d, "
                "binlog file %s is not a regular file!",
                __LINE__, filename);
        return EINVAL;
    }

    fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        result = errno != 0 ? errno : EPERM;
        if (result == ENOENT) {
            return 0;
        } else {
            logError("file: "__FILE__", line: %d, "
                    "open binlog file %s fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
            return result;
        }
    }

    if (stbuf.st_size <= 64 * 1024) {
        buffer.alloc_size = 64 * 1024;
    } else if (stbuf.st_size <= 256 * 1024) {
        buffer.alloc_size = 256 * 1024;
    } else if (stbuf.st_size <= 1 * 1024 * 1024) {
        buffer.alloc_size = 1 * 1024 * 1024;
    } else if (stbuf.st_size <= 4 * 1024 * 1024) {
        buffer.alloc_size = 4 * 1024 * 1024;
    } else if (stbuf.st_size <= 16 * 1024 * 1024) {
        buffer.alloc_size = 16 * 1024 * 1024;
    } else {
        buffer.alloc_size = 64 * 1024 * 1024;
    }

    if ((buffer.buff=fc_malloc(buffer.alloc_size)) == NULL) {
        close(fd);
        return ENOMEM;
    }

    line_count = 0;
    result = 0;
    while (1) {
        buffer.length = fc_read_lines(fd, buffer.buff, buffer.alloc_size);
        if (buffer.length == 0) {
            break;
        } else if (buffer.length < 0) {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "read from file %s fail, errno: %d, error info: %s",
                    __LINE__, filename, result, STRERROR(result));
            break;
        }

        if ((result=parse_buffer(filename, &buffer, &line_count,
                        unpack_func, args)) != 0)
        {
            break;
        }
    }

    close(fd);
    free(buffer.buff);
    return result;
}

int da_binlog_reader_load(const uint64_t id, void *args)
{
    char filename[PATH_MAX];

    da_write_fd_cache_filename(id, filename, sizeof(filename));
    return da_binlog_reader_load_ex(filename, g_disk_allocator_vars.
            unpack_record, args);
}
