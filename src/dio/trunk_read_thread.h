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


#ifndef _DA_TRUNK_READ_THREAD_H
#define _DA_TRUNK_READ_THREAD_H

#include "fastcommon/common_define.h"
#ifdef OS_LINUX
#include <libaio.h>
#endif
#include "../storage_config.h"
#include "../storage_allocator.h"
#ifdef OS_LINUX
#include "read_buffer_pool.h"
#endif

struct da_trunk_read_io_buffer;

//Note: the record can NOT be persisted
typedef void (*da_trunk_read_io_notify_func)(struct da_trunk_read_io_buffer
        *record, const int result);

typedef struct da_trunk_read_io_buffer {
    DATrunkSpaceInfo space;
    int read_bytes;

    DATrunkReadBuffer *rb;
#ifdef OS_LINUX
    struct iocb iocb;
#endif

    struct {
        da_trunk_read_io_notify_func func;
        void *arg;
    } notify;

    struct da_trunk_read_io_buffer *next;
} DATrunkReadIOBuffer;

typedef struct da_synchronized_read_context {
    SFSynchronizeContext sctx;
    DASliceOpContext op_ctx;
} DASynchronizedReadContext;

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_read_thread_init(DAContext *ctx);
    void da_trunk_read_thread_terminate(DAContext *ctx);

#ifdef OS_LINUX
    static inline DAAlignedReadBuffer *da_aligned_buffer_new(
            DAContext *ctx, const short pindex, const int offset,
            const int length, const int read_bytes,
            const int align_block_count)
    {
        DAAlignedReadBuffer *aligned_buffer;

        aligned_buffer = da_read_buffer_pool_alloc(ctx, pindex,
                read_bytes, align_block_count);
        if (aligned_buffer == NULL) {
            return NULL;
        }

        aligned_buffer->offset = offset;
        aligned_buffer->length = length;
        aligned_buffer->read_bytes = read_bytes;
        return aligned_buffer;
    }
#endif

    /* MUST set rb->type in Linux before call this function */
    int da_trunk_read_thread_push(DAContext *ctx,
            const DATrunkSpaceInfo *space,
            const int read_bytes, DATrunkReadBuffer *rb,
            da_trunk_read_io_notify_func notify_func, void *notify_arg);

    int da_init_read_context(DASynchronizedReadContext *rctx);

    int da_slice_read(DAContext *ctx, DASynchronizedReadContext *rctx);

#ifdef __cplusplus
}
#endif

#endif
