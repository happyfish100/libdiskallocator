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
} DAStorageAllocatorContext;

typedef struct {
    DAStorageAllocatorContext write_cache;
    DAStorageAllocatorContext store_path;
    DATrunkFreelist reclaim_freelist;  //special purpose for reclaiming
    DATrunkAllocatorPtrArray allocator_ptr_array; //by store path index
    struct fast_mblock_man aptr_array_allocator;
    pthread_mutex_t lock;
    int64_t current_trunk_id;
} DAStorageAllocatorManager;

#ifdef __cplusplus
extern "C" {
#endif

    extern DAStorageAllocatorManager *g_da_allocator_mgr;

    int da_storage_allocator_init();

    int da_storage_allocator_prealloc_trunk_freelists();

    static inline int da_storage_allocator_add_trunk_ex(const int path_index,
            const DATrunkIdInfo *id_info, const int64_t size,
            DATrunkFileInfo **pp_trunk)
    {
        int result;

        if ((result=da_trunk_id_info_add(path_index, id_info)) != 0) {
            return result;
        }

        return da_trunk_allocator_add(g_da_allocator_mgr->allocator_ptr_array.
                allocators[path_index], id_info, size, pp_trunk);
    }

    static inline int da_storage_allocator_add_trunk(const int path_index,
            const DATrunkIdInfo *id_info, const int64_t size)
    {
        return da_storage_allocator_add_trunk_ex(path_index, id_info, size, NULL);
    }

    static inline int da_storage_allocator_delete_trunk(const int path_index,
            const DATrunkIdInfo *id_info)
    {
        int result;
        if ((result=da_trunk_id_info_delete(path_index, id_info)) != 0) {
            return result;
        }
        return da_trunk_allocator_delete(g_da_allocator_mgr->allocator_ptr_array.
                allocators[path_index], id_info->id);
    }

    static inline int da_storage_allocator_normal_alloc_ex(
            const uint64_t blk_hc, const int size,
            DATrunkSpaceInfo *spaces,
            int *count, const bool is_normal)
    {
        DATrunkAllocatorPtrArray *avail_array;
        DATrunkAllocator **allocator;
        int result;

        do {
            avail_array = (DATrunkAllocatorPtrArray *)
                g_da_allocator_mgr->store_path.avail;
            if (avail_array->count == 0) {
                result = ENOSPC;
                break;
            }

            allocator = avail_array->allocators +
                blk_hc % avail_array->count;
            result = da_trunk_freelist_alloc_space(*allocator,
                    &(*allocator)->freelist, blk_hc, size,
                    spaces, count, is_normal);
        } while ((result == ENOSPC || result == EAGAIN) && is_normal);

        return result;
    }

    static inline int da_storage_allocator_reclaim_alloc(const uint64_t blk_hc,
            const int size, DATrunkSpaceInfo *spaces, int *count)
    {
        const bool is_normal = false;
        int result;

        if ((result=da_storage_allocator_normal_alloc_ex(blk_hc,
                        size, spaces, count, is_normal)) == 0)
        {
            return result;
        }

        return da_trunk_freelist_alloc_space(NULL,
                &g_da_allocator_mgr->reclaim_freelist, blk_hc,
                size, spaces, count, is_normal);
    }

#define da_storage_allocator_normal_alloc(blk_hc, size, spaces, count) \
    da_storage_allocator_normal_alloc_ex(blk_hc, size, spaces, count, true)

    int da_move_allocator_ptr_array(DATrunkAllocatorPtrArray **src_array,
            DATrunkAllocatorPtrArray **dest_array, DATrunkAllocator *allocator);

    static inline int da_add_to_avail_aptr_array(DAStorageAllocatorContext
            *allocator_ctx, DATrunkAllocator *allocator)
    {
        int result;
        if ((result=da_move_allocator_ptr_array((DATrunkAllocatorPtrArray **)
                        &allocator_ctx->full, (DATrunkAllocatorPtrArray **)
                        &allocator_ctx->avail, allocator)) == 0)
        {
            logInfo("file: "__FILE__", line: %d, "
                    "path: %s is available", __LINE__,
                    allocator->path_info->store.path.str);
        } else {
            logWarning("file: "__FILE__", line: %d, "
                    "path: %s set available fail, errno: %d, "
                    "error info: %s", __LINE__, allocator->path_info->
                    store.path.str,  result, STRERROR(result));
        }

        return result;
    }

    static inline int da_remove_from_avail_aptr_array(DAStorageAllocatorContext
            *allocator_ctx, DATrunkAllocator *allocator)
    {
        int result;
        if ((result=da_move_allocator_ptr_array((DATrunkAllocatorPtrArray **)
                        &allocator_ctx->avail, (DATrunkAllocatorPtrArray **)
                        &allocator_ctx->full, allocator)) == 0)
        {
            allocator->path_info->trunk_stat.last_used = __sync_add_and_fetch(
                    &allocator->path_info->trunk_stat.used, 0);
            logWarning("file: "__FILE__", line: %d, "
                    "path: %s is full", __LINE__,
                    allocator->path_info->store.path.str);
        } else {
            logWarning("file: "__FILE__", line: %d, "
                    "path: %s set full fail, errno: %d, "
                    "error info: %s", __LINE__, allocator->path_info->
                    store.path.str,  result, STRERROR(result));
        }

        return result;
    }

    static inline int da_storage_allocator_avail_count()
    {
        return g_da_allocator_mgr->store_path.avail->count;
    }

    int da_storage_allocator_trunks_to_array(SFBinlogIndexArray *array);

#ifdef __cplusplus
}
#endif

#endif
