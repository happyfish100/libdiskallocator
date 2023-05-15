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


#ifndef _DA_TRUNK_WRITE_THREAD_H
#define _DA_TRUNK_WRITE_THREAD_H

#include "../storage_config.h"
#include "../storage_allocator.h"

#define DA_IO_TYPE_CREATE_TRUNK           'C'
#define DA_IO_TYPE_DELETE_TRUNK           'D'
#define DA_IO_TYPE_WRITE_SLICE_BY_BUFF    'W'
#define DA_IO_TYPE_WRITE_SLICE_BY_IOVEC   'V'
#define DA_IO_TYPE_QUIT                   'Q'

struct da_trunk_write_io_buffer;

//Note: the record can NOT be persisted
typedef void (*da_trunk_write_io_notify_func)(struct da_trunk_write_io_buffer
        *record, const int result);

typedef struct da_slice_entry {
    uint32_t timestamp;
    char source;
    SFBlockSliceKeyInfo bs_key;
    uint64_t data_version;
    uint64_t sn;
} DASliceEntry;

typedef struct da_trunk_write_io_buffer {
    int op_type;
    DASliceType slice_type;  //in file, write cache or memory as fallocate
    DATrunkSpaceInfo space;

    int64_t version; //for write in order

    union {
        char *buff;
        iovec_array_t iovec_array;
    };

    union {
        struct {
            da_trunk_write_io_notify_func func;
            void *arg1;
            void *arg2;
        } notify;

        struct {
            DASliceEntry slice;
            void *arg;
        };  //for slice_type == DA_SLICE_TYPE_CACHE
    };

    struct da_trunk_write_io_buffer *next;
} TrunkWriteIOBuffer;


#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_write_thread_init(DAContext *ctx);
    void da_trunk_write_thread_terminate(DAContext *ctx);

    int da_trunk_write_thread_push(DAContext *ctx, const int op_type,
            const int64_t version, const DATrunkSpaceInfo *space,
            void *data, da_trunk_write_io_notify_func notify_func,
            void *arg1, void *arg2);

    static inline int da_trunk_write_thread_push_trunk_op(DAContext *ctx,
            const int op_type, const DATrunkSpaceInfo *space,
            da_trunk_write_io_notify_func notify_func, void *notify_arg)
    {
        DATrunkAllocator *allocator;
        allocator = ctx->store_allocator_mgr->allocator_ptr_array.
            allocators[space->store->index];
        return da_trunk_write_thread_push(ctx, op_type, __sync_add_and_fetch(
                    &allocator->allocate.current_version, 1), space,
                NULL, notify_func, notify_arg, NULL);
    }

    int da_trunk_write_thread_push_cached_slice(DAContext *ctx,
            const int op_type, const int64_t version,
            const DATrunkSpaceInfo *space, void *data,
            const DASliceEntry *slice, void *arg);

    static inline int da_trunk_write_thread_push_slice_by_buff(
            DAContext *ctx, const int64_t version, DATrunkSpaceInfo *space,
            char *buff, da_trunk_write_io_notify_func notify_func,
            void *arg1, void *arg2)
    {
        return da_trunk_write_thread_push(ctx, DA_IO_TYPE_WRITE_SLICE_BY_BUFF,
                version, space, buff, notify_func, arg1, arg2);
    }

    int da_trunk_write_thread_by_buff_synchronize(DAContext *ctx,
            DATrunkSpaceWithVersion *space_info, char *buff,
            SFSynchronizeContext *sctx);

    static inline int da_trunk_write_thread_push_slice_by_iovec(
            DAContext *ctx, const int64_t version, DATrunkSpaceInfo *space,
            iovec_array_t *iovec_array, da_trunk_write_io_notify_func notify_func,
            void *arg1, void *arg2)
    {
        return da_trunk_write_thread_push(ctx, DA_IO_TYPE_WRITE_SLICE_BY_IOVEC,
                version, space, iovec_array, notify_func, arg1, arg2);
    }

#ifdef __cplusplus
}
#endif

#endif
