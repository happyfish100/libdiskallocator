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

//binlog_writer.h

#ifndef _DA_BINLOG_WRITER_H_
#define _DA_BINLOG_WRITER_H_

#include "fastcommon/shared_func.h"
#include "../common/binlog_types.h"

typedef struct {
    DABinlogIdTypePair key;
    char buff[16 * 1024];
    char *current;
    char *buff_end;
    int fd;
} DABinlogWriterCache;

#ifdef __cplusplus
extern "C" {
#endif

static inline void da_binlog_writer_cache_init(DABinlogWriterCache *cache)
{
    cache->key.id = 0;
    cache->key.type = 0;
    cache->fd = -1;
    cache->current = cache->buff;
    cache->buff_end = cache->buff + sizeof(cache->buff);
}

static inline int da_binlog_writer_cache_write(DABinlogWriterCache *cache)
{
    int len;

    if ((len=cache->current - cache->buff) == 0) {
        return 0;
    }

    cache->current = cache->buff;
    return fc_safe_write(cache->fd, cache->buff, len);
}

int da_binlog_writer_global_init();

int da_binlog_writer_init(DABinlogWriter *writer, const int type,
        const int max_record_size);

int da_binlog_writer_log(DABinlogWriter *writer, const uint64_t binlog_id,
        const BufferInfo *buffer);

int da_binlog_writer_synchronize(DABinlogWriter *writer);

int da_binlog_writer_shrink(DABinlogWriter *writer, void *args);

void da_binlog_writer_finish();

#ifdef __cplusplus
}
#endif

#endif
