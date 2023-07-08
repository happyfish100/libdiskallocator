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


#ifndef _DA_READ_BUFFER_POOL_H
#define _DA_READ_BUFFER_POOL_H

#include "fastcommon/fc_list.h"
#include "sf/sf_types.h"
#include "sf/sf_global.h"

struct da_context;
typedef struct da_aligned_read_buffer {
    char *buff;  //aligned by device block size
    int offset;  //data offset
    int length;  //data length
    int read_bytes;
    int size;
    struct {
        short path;
        short allocator;
    } indexes;
    time_t last_access_time;
    struct fc_list_head dlink;  //for freelist
} DAAlignedReadBuffer;

#ifdef __cplusplus
extern "C" {
#endif

    int da_read_buffer_pool_init(struct da_context *ctx, const int path_count,
            const SFMemoryWatermark *watermark);

    int da_read_buffer_pool_start(struct da_context *ctx,
            const int max_idle_time, const int reclaim_interval);

    int da_read_buffer_pool_create(struct da_context *ctx,
            const short path_index, const int block_size);

    DAAlignedReadBuffer *da_read_buffer_pool_alloc(struct da_context *ctx,
            const short path_index, const int size, const int align_block_count);

    void da_read_buffer_pool_free(struct da_context *ctx,
            DAAlignedReadBuffer *buffer);

#ifdef __cplusplus
}
#endif

#endif
