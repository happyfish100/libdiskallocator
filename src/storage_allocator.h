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


#ifndef _DA_STORAGE_ALLOCATOR_H
#define _DA_STORAGE_ALLOCATOR_H

#include "fastcommon/fc_atomic.h"
#include "sf/sf_binlog_index.h"
#include "trunk/trunk_id_info.h"
#include "trunk/trunk_freelist.h"
#include "trunk/trunk_allocator.h"

typedef struct {
    int count;
    DATrunkAllocator *allocators;
} DATrunkAllocatorArray;

typedef struct {
    int count;
    int alloc;
    DATrunkAllocator **allocators;
} DATrunkAllocatorPtrArray;

typedef struct {
    DATrunkAllocatorArray all;
    volatile DATrunkAllocatorPtrArray *full;
    volatile DATrunkAllocatorPtrArray *avail;
    time_t last_change_time;
} DAStorageAllocatorContext;

typedef struct da_storage_allocator_manager {
    DAStorageAllocatorContext write_cache;
    DAStorageAllocatorContext store_path;
    DATrunkFreelist reclaim_freelist;  //special purpose for reclaiming
    DATrunkAllocatorPtrArray allocator_ptr_array; //by store path index
    struct fast_mblock_man aptr_array_allocator;
    pthread_mutex_t lock;
    uint64_t current_trunk_id;
} DAStorageAllocatorManager;

#ifdef __cplusplus
extern "C" {
#endif

    int da_storage_allocator_init(DAContext *ctx);

    int da_storage_allocator_prealloc_trunk_freelists(DAContext *ctx);
    void da_storage_allocator_wait_available(DAContext *ctx);

    static inline int da_storage_allocator_add_trunk_ex(DAContext *ctx,
            const int path_index, const DATrunkIdInfo *id_info,
            const int64_t size, DATrunkFileInfo **pp_trunk)
    {
        int result;

        if ((result=da_trunk_id_info_add(ctx, path_index, id_info)) != 0) {
            return result;
        }

        return da_trunk_allocator_add(ctx->store_allocator_mgr->
                allocator_ptr_array.allocators[path_index],
                id_info, size, pp_trunk);
    }

    static inline int da_storage_allocator_add_trunk(DAContext *ctx,
            const int path_index, const DATrunkIdInfo *id_info,
            const int64_t size)
    {
        return da_storage_allocator_add_trunk_ex(ctx,
                path_index, id_info, size, NULL);
    }

    static inline int da_storage_allocator_delete_trunk(DAContext *ctx,
            const int path_index, const DATrunkIdInfo *id_info)
    {
        int result;
        if ((result=da_trunk_id_info_delete(ctx, path_index, id_info)) != 0) {
            return result;
        }
        return da_trunk_allocator_delete(ctx->store_allocator_mgr->
                allocator_ptr_array.allocators[path_index], id_info->id);
    }

    static inline int da_storage_allocator_alloc_space(
            DAContext *ctx, const uint64_t blk_hc, const int size,
            DATrunkSpaceWithVersion *spaces, int *count,
            const bool is_normal, const DASliceType slice_type)
    {
        DATrunkAllocatorPtrArray *avail_array;
        DATrunkAllocator **allocator;
        int result;

        result = ENOSPC;
        do {
            while (1) {
                avail_array = (DATrunkAllocatorPtrArray *)
                    ctx->store_allocator_mgr->store_path.avail;
                if (avail_array->count > 0) {
                    break;
                }

                if (g_current_time - ctx->store_allocator_mgr->
                        store_path.last_change_time > 300)
                {
                    return ENOSPC;
                }
                if (is_normal && SF_G_CONTINUE_FLAG) {
                    fc_sleep_ms(1);
                } else {
                    return ENOSPC;
                }
            }

            allocator = avail_array->allocators + blk_hc % avail_array->count;
            if ((result=da_trunk_freelist_alloc_space(*allocator,
                            &(*allocator)->freelist, blk_hc, size,
                            spaces, count, is_normal, slice_type)) == 0)
            {
                return 0;
            }
        } while ((result == ENOSPC || result == EAGAIN) &&
                is_normal && SF_G_CONTINUE_FLAG);

        return result;
    }

    static inline int da_storage_allocator_reclaim_alloc(DAContext *ctx,
            const uint64_t blk_hc, const int size,
            DATrunkSpaceWithVersion *spaces, int *count,
            const DASliceType slice_type)
    {
        const bool is_normal = false;
        int result;

        if ((result=da_storage_allocator_alloc_space(ctx, blk_hc, size,
                        spaces, count, is_normal, slice_type)) == 0)
        {
            return result;
        }

        return da_trunk_freelist_alloc_space(NULL, &ctx->
                store_allocator_mgr->reclaim_freelist, blk_hc,
                size, spaces, count, is_normal, slice_type);
    }

#define da_storage_allocator_normal_alloc_ex(ctx, \
        blk_hc, size, spaces, count, slice_type)  \
    da_storage_allocator_alloc_space(ctx, blk_hc, \
            size, spaces, count, true, slice_type)

#define da_storage_allocator_normal_alloc(ctx, blk_hc, size, spaces, count) \
    da_storage_allocator_normal_alloc_ex(ctx, blk_hc, \
            size, spaces, count, DA_SLICE_TYPE_FILE)

    int da_move_allocator_ptr_array(DAContext *ctx, DATrunkAllocatorPtrArray
            **src_array, DATrunkAllocatorPtrArray **dest_array,
            DATrunkAllocator *allocator);

    static inline int da_add_to_avail_aptr_array(DAContext *ctx,
            DAStorageAllocatorContext *allocator_ctx,
            DATrunkAllocator *allocator)
    {
        int result;
        if ((result=da_move_allocator_ptr_array(ctx,
                        (DATrunkAllocatorPtrArray **)&allocator_ctx->full,
                        (DATrunkAllocatorPtrArray **)&allocator_ctx->avail,
                        allocator)) == 0)
        {
            allocator_ctx->last_change_time = g_current_time;
            logInfo("file: "__FILE__", line: %d, %s "
                    "path: %s is available", __LINE__, ctx->module_name,
                    allocator->path_info->store.path.str);
        } else {
            logWarning("file: "__FILE__", line: %d, %s "
                    "path: %s set available fail, errno: %d, "
                    "error info: %s", __LINE__, ctx->module_name,
                    allocator->path_info->store.path.str,
                    result, STRERROR(result));
        }

        return result;
    }

    static inline int da_remove_from_avail_aptr_array(DAContext *ctx,
            DAStorageAllocatorContext *allocator_ctx,
            DATrunkAllocator *allocator)
    {
        int result;
        if ((result=da_move_allocator_ptr_array(ctx,
                        (DATrunkAllocatorPtrArray **)&allocator_ctx->avail,
                        (DATrunkAllocatorPtrArray **)&allocator_ctx->full,
                        allocator)) == 0)
        {
            allocator_ctx->last_change_time = g_current_time;
            allocator->path_info->trunk_stat.last_used =
                FC_ATOMIC_GET(allocator->path_info->trunk_stat.used);
            logWarning("file: "__FILE__", line: %d, %s "
                    "path: %s is full", __LINE__, ctx->module_name,
                    allocator->path_info->store.path.str);
        } else {
            logWarning("file: "__FILE__", line: %d, %s "
                    "path: %s set full fail, errno: %d, "
                    "error info: %s", __LINE__, ctx->module_name,
                    allocator->path_info->store.path.str,
                    result, STRERROR(result));
        }

        return result;
    }

    static inline int da_storage_allocator_avail_count(DAContext *ctx)
    {
        return ctx->store_allocator_mgr->store_path.avail->count;
    }

    int da_storage_allocator_trunks_to_array(DAContext *ctx,
            SFBinlogIndexArray *array, int *changed_count);

#ifdef __cplusplus
}
#endif

#endif
