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


#ifndef _DA_TRUNK_ALLOCATOR_H
#define _DA_TRUNK_ALLOCATOR_H

#include "fastcommon/uniq_skiplist.h"
#include "fastcommon/fc_list.h"
#include "trunk_freelist.h"
#include "../global.h"

#define DA_TRUNK_SKIPLIST_INIT_LEVEL_COUNT       6
#define DA_TRUNK_SKIPLIST_MAX_LEVEL_COUNT       12
#define DA_TRUNK_SKIPLIST_DELAY_FREE_SECONDS   600

#define DA_TRUNK_STATUS_NONE        0
#define DA_TRUNK_STATUS_LOADED      1
#define DA_TRUNK_STATUS_REPUSH      2  //intermediate state
#define DA_TRUNK_STATUS_ALLOCING    3
#define DA_TRUNK_STATUS_RECLAIMING  4

#define DA_TRUNK_UTIL_EVENT_NONE      0
#define DA_TRUNK_UTIL_EVENT_CREATE   'C'
#define DA_TRUNK_UTIL_EVENT_UPDATE   'U'

#define DA_TRUNK_AVAIL_SPACE(trunk) ((trunk)->size - (trunk)->free_start)

typedef enum {
    da_freelist_type_none,
    da_freelist_type_normal,
    da_freelist_type_reclaim
} DATrunkFreelistType;

typedef struct {
    int alloc;
    int count;
    DATrunkFileInfo **trunks;
} DATrunkInfoPtrArray;

typedef struct da_trunk_allocator {
    DAStoragePathInfo *path_info;
    struct {
        UniqSkiplistPair by_id;   //order by trunk id
        UniqSkiplistPair by_size; //order by used size and trunk id
    } trunks;
    DATrunkFreelist freelist; //trunk freelist pool

    struct {
        time_t last_trigger_time; //caller trigger create trunk
        int creating_trunks;  //counter for creating (prealloc or reclaim) trunk
        int waiting_callers;  //caller count for waiting available trunk
        volatile int64_t current_version; //for trunk space alloc
    } allocate; //for allocate space

    struct {
        time_t last_deal_time;
        int last_errno;
        struct fc_queue queue;  //trunk event queue for nodify
        struct da_trunk_allocator *next; //for event notify queue
    } reclaim; //for trunk reclaim
} DATrunkAllocator;

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_allocator_init_instance(DATrunkAllocator *allocator,
            DAStoragePathInfo *path_info);

    int da_trunk_allocator_add(DATrunkAllocator *allocator,
            const DATrunkIdInfo *id_info, const int64_t size,
            DATrunkFileInfo **pp_trunk);

    int da_trunk_allocator_delete(DATrunkAllocator *allocator, const int64_t id);

    int da_trunk_allocator_free(DATrunkAllocator *allocator,
            const int id, const int size);

    DATrunkFreelistType da_trunk_allocator_add_to_freelist(
            DATrunkAllocator *allocator, DATrunkFileInfo *trunk_info);

    void da_trunk_allocator_deal_on_ready(DATrunkAllocator *allocator);

    static inline bool da_trunk_allocator_is_available(DATrunkAllocator *allocator)
    {
        return allocator->freelist.count >=
            allocator->freelist.water_mark_trunks;
    }

    void da_trunk_allocator_log_trunk_info(DATrunkFileInfo *trunk_info);

    static inline int da_compare_trunk_by_size_id(const DATrunkFileInfo *t1,
            const int64_t last_used_bytes2, const int64_t id2)
    {
        int sub;

        if ((sub=fc_compare_int64(t1->util.last_used_bytes,
                        last_used_bytes2)) != 0)
        {
            return sub;
        }

        return fc_compare_int64(t1->id_info.id, id2);
    }

    static inline int da_trunk_allocator_get_freelist_count(
            DATrunkAllocator *allocator)
    {
        int count;
        PTHREAD_MUTEX_LOCK(&allocator->freelist.lcp.lock);
        count = allocator->freelist.count;
        PTHREAD_MUTEX_UNLOCK(&allocator->freelist.lcp.lock);
        return count;
    }

    static inline void da_set_trunk_status(DATrunkFileInfo *trunk,
            const int new_status)
    {
        int old_status;

        old_status = __sync_add_and_fetch(&trunk->status, 0);
        while (new_status != old_status) {
            if (__sync_bool_compare_and_swap(&trunk->status,
                        old_status, new_status))
            {
                break;
            }
            old_status = __sync_add_and_fetch(&trunk->status, 0);
        }
    }

    static inline void da_trunk_allocator_before_make_trunk(
            DATrunkAllocator *allocator, const bool need_lock)
    {
        if (need_lock) {
            PTHREAD_MUTEX_LOCK(&allocator->freelist.lcp.lock);
        }
        allocator->allocate.creating_trunks++;
        if (need_lock) {
            PTHREAD_MUTEX_UNLOCK(&allocator->freelist.lcp.lock);
        }
    }

    static inline void da_trunk_allocator_after_make_trunk(
            DATrunkAllocator *allocator, const int result)
    {
        PTHREAD_MUTEX_LOCK(&allocator->freelist.lcp.lock);
        allocator->reclaim.last_errno = result;
        allocator->allocate.creating_trunks--;
        if (allocator->allocate.waiting_callers > 0) {
            pthread_cond_broadcast(&allocator->freelist.lcp.cond);
        }
        PTHREAD_MUTEX_UNLOCK(&allocator->freelist.lcp.lock);
    }

    static inline double da_trunk_allocator_calc_reclaim_ratio_thredhold(
            DATrunkAllocator *allocator)
    {
        double used_ratio;
        used_ratio = allocator->path_info->space_stat.used_ratio
            + allocator->path_info->reserved_space.ratio;
        if (used_ratio >= 1.00) {
            return allocator->path_info->ctx->storage.cfg.
                never_reclaim_on_trunk_usage;
        } else {
            return allocator->path_info->ctx->storage.cfg.
                never_reclaim_on_trunk_usage * (used_ratio -
                        allocator->path_info->ctx->storage.cfg.
                        reclaim_trunks_on_path_usage) / (1.00 -
                            allocator->path_info->ctx->storage.cfg.
                            reclaim_trunks_on_path_usage);
        }
    }

    int da_trunk_allocator_deal_space_changes(DAContext *ctx,
            DATrunkFileInfo *trunk, DATrunkSpaceLogRecord **records,
            const int count, uint32_t *used_bytes);

#ifdef __cplusplus
}
#endif

#endif
