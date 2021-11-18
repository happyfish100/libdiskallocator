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


#ifndef _TRUNK_READ_THREAD_H
#define _TRUNK_READ_THREAD_H

#include "fastcommon/common_define.h"
#ifdef OS_LINUX
#include <libaio.h>
#endif
#include "../storage_config.h"
#include "../storage_allocator.h"
#ifdef OS_LINUX
#include "read_buffer_pool.h"
#endif

struct trunk_read_io_buffer;

//Note: the record can NOT be persisted
typedef void (*trunk_read_io_notify_func)(struct trunk_read_io_buffer
        *record, const int result);

typedef struct trunk_read_io_buffer {
    DATrunkSpaceInfo space;
    int read_bytes;
    char *data;

#ifdef OS_LINUX
    AlignedReadBuffer **aligned_buffer;
    struct iocb iocb;
#endif

    struct {
        trunk_read_io_notify_func func;
        void *arg;
    } notify;

    struct trunk_read_io_buffer *next;
} TrunkReadIOBuffer;

typedef struct da_synchronized_read_context {
    SFSynchronizeContext sctx;
    DASliceOpContext op_ctx;
} DASynchronizedReadContext;

#ifdef __cplusplus
extern "C" {
#endif

    int trunk_read_thread_init();
    void trunk_read_thread_terminate();

#ifdef OS_LINUX

    static inline int da_init_op_ctx(DASliceOpContext *op_ctx)
    {
        op_ctx->storage = NULL;
        op_ctx->aio_buffer = NULL;
        return 0;
    }

    int trunk_read_thread_push(const DATrunkSpaceInfo *space,
            const int read_bytes, AlignedReadBuffer **aligned_buffer,
            trunk_read_io_notify_func notify_func, void *notify_arg);

#else

    static inline int da_init_op_ctx(DASliceOpContext *op_ctx)
    {
        const int alloc_size = 64 * 1024;
        op_ctx->storage = NULL;
        return fc_init_buffer(&op_ctx->buffer, alloc_size);
    }

    int trunk_read_thread_push(const DATrunkSpaceInfo *space,
            const int read_bytes, char *buff, trunk_read_io_notify_func
            notify_func, void *notify_arg);

#endif

    int da_slice_read(DASliceOpContext *op_ctx, SFSynchronizeContext *sctx);

    static inline int da_slice_read1(DASynchronizedReadContext *context)
    {
        return da_slice_read(&context->op_ctx, &context->sctx);
    }

#ifdef __cplusplus
}
#endif

#endif
