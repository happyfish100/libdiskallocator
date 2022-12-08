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
#include "fastcommon/fc_atomic.h"
#include "sf/sf_func.h"
#include "../common/binlog_types.h"

typedef struct {
    uint64_t id;
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
    cache->id = 0;
    cache->fd = -1;
    cache->current = cache->buff;
    cache->buff_end = cache->buff + sizeof(cache->buff);
}


int da_binlog_writer_cache_write(DABinlogWriterCache *cache, const bool flush);

int da_binlog_writer_global_init();

int da_binlog_writer_init(DABinlogWriter *writer,
        const int max_record_size);

int da_binlog_writer_start();

int da_binlog_writer_log(DABinlogWriter *writer, const uint64_t binlog_id,
        const BufferInfo *buffer);

int da_binlog_writer_synchronize(DABinlogWriter *writer);

int da_binlog_writer_shrink(DABinlogWriter *writer, const int64_t id,
        const time_t last_shrink_time, void *args);

int da_binlog_writer_clear_fd_cache();

void da_binlog_writer_finish();

static inline void da_binlog_writer_inc_waiting_count(
        DABinlogWriter *writer, const int count)
{
    sf_synchronize_counter_add(&writer->notify, count);
}

static inline int da_binlog_writer_get_waiting_count(
        DABinlogWriter *writer)
{
    int waiting_count;

    PTHREAD_MUTEX_LOCK(&writer->notify.lcp.lock);
    waiting_count = writer->notify.waiting_count;
    PTHREAD_MUTEX_UNLOCK(&writer->notify.lcp.lock);
    return waiting_count;
}

static inline void da_binlog_writer_wait(DABinlogWriter *writer)
{
    sf_synchronize_counter_wait(&writer->notify);
}

#ifdef __cplusplus
}
#endif

#endif
