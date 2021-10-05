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


#ifndef _TRUNK_WRITE_THREAD_H
#define _TRUNK_WRITE_THREAD_H

#include "../storage_config.h"
#include "../storage_allocator.h"

#define DA_IO_TYPE_CREATE_TRUNK           'C'
#define DA_IO_TYPE_DELETE_TRUNK           'D'
#define DA_IO_TYPE_WRITE_SLICE_BY_BUFF    'W'
#define DA_IO_TYPE_WRITE_SLICE_BY_IOVEC   'V'

struct trunk_write_io_buffer;

//Note: the record can NOT be persisted
typedef void (*trunk_write_io_notify_func)(struct trunk_write_io_buffer
        *record, const int result);

typedef struct trunk_write_io_buffer {
    int type;
    DATrunkSpaceInfo space;
    int64_t version; //for write in order

    union {
        char *buff;
        iovec_array_t iovec_array;
    };

    struct {
        trunk_write_io_notify_func func;
        void *arg;
    } notify;
    struct trunk_write_io_buffer *next;
} TrunkWriteIOBuffer;

#ifdef __cplusplus
extern "C" {
#endif

    int trunk_write_thread_init();
    void trunk_write_thread_terminate();

    int trunk_write_thread_push(const int type, const int64_t version,
            const DATrunkSpaceInfo *space, void *data,
            trunk_write_io_notify_func notify_func, void *notify_arg);

    static inline int trunk_write_thread_push_trunk_op(const int type,
            const DATrunkSpaceInfo *space, trunk_write_io_notify_func
            notify_func, void *notify_arg)
    {
        DATrunkAllocator *allocator;
        allocator = g_allocator_mgr->allocator_ptr_array.
            allocators[space->store->index];
        return trunk_write_thread_push(type, __sync_add_and_fetch(
                    &allocator->allocate.current_version, 1), space,
                NULL, notify_func, notify_arg);
    }

    static inline int trunk_write_thread_push_slice_by_buff_ex(
            const int64_t version, DATrunkSpaceInfo *space, char *buff,
            trunk_write_io_notify_func notify_func, void *notify_arg)
    {
        return trunk_write_thread_push(DA_IO_TYPE_WRITE_SLICE_BY_BUFF,
                version, space, buff, notify_func, notify_arg);
    }

    static inline int trunk_write_thread_push_slice_by_buff(
            DATrunkSpaceInfo *space, char *buff,
            trunk_write_io_notify_func notify_func, void *notify_arg)
    {
        DATrunkAllocator *allocator;
        allocator = g_allocator_mgr->allocator_ptr_array.
            allocators[space->store->index];
        return trunk_write_thread_push(DA_IO_TYPE_WRITE_SLICE_BY_BUFF,
                __sync_add_and_fetch(&allocator->allocate.current_version, 1),
                space, buff, notify_func, notify_arg);
    }

    int trunk_write_thread_by_buff_synchronize(DATrunkSpaceInfo *space,
            char *buff, SFSynchronizeContext *sctx);

    static inline int trunk_write_thread_push_slice_by_iovec(
            const int64_t version, DATrunkSpaceInfo *space, iovec_array_t
            *iovec_array, trunk_write_io_notify_func notify_func,
            void *notify_arg)
    {
        return trunk_write_thread_push(DA_IO_TYPE_WRITE_SLICE_BY_IOVEC,
                version, space, iovec_array, notify_func, notify_arg);
    }

#ifdef __cplusplus
}
#endif

#endif
