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

#include <limits.h>
#include <assert.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "../global.h"
#include "../storage_allocator.h"
#include "trunk_maker.h"
#include "trunk_freelist.h"

int trunk_freelist_init(DATrunkFreelist *freelist)
{
    int result;
    if ((result=init_pthread_lock_cond_pair(&freelist->lcp)) != 0) {
        return result;
    }

    freelist->water_mark_trunks = 2;
    return 0;
}

static inline void push_trunk_util_event_force(DATrunkAllocator *allocator,
        DATrunkFileInfo *trunk, const int event)
{
    int old_event;

    while (1) {
        old_event = __sync_add_and_fetch(&trunk->util.event, 0);
        if (event == old_event) {
            return;
        }

        if (__sync_bool_compare_and_swap(&trunk->util.event,
                    old_event, event))
        {
            if (old_event == DA_TRUNK_UTIL_EVENT_NONE) {
                fc_queue_push(&allocator->reclaim.queue, trunk);
            }
            return;
        }
    }
}

#define TRUNK_ALLOC_SPACE(trunk, space_info, alloc_size) \
    do { \
        space_info->store = &trunk->allocator->path_info->store; \
        space_info->id_info = trunk->id_info;   \
        space_info->offset = trunk->free_start; \
        space_info->size = alloc_size;          \
        trunk->free_start += alloc_size;  \
        __sync_sub_and_fetch(&trunk->allocator->path_info-> \
                trunk_stat.avail, alloc_size);  \
    } while (0)

void trunk_freelist_keep_water_mark(struct da_trunk_allocator
        *allocator)
{
    int count;
    int i;

    count = allocator->freelist.water_mark_trunks - allocator->freelist.count;
    if (count <= 0) {
        logInfo("file: "__FILE__", line: %d, "
                "path: %s, freelist count: %d, water_mark count: %d",
                __LINE__, allocator->path_info->store.path.str,
                allocator->freelist.count,
                allocator->freelist.water_mark_trunks);
        return;
    }

    logInfo("file: "__FILE__", line: %d, "
            "path: %s, freelist count: %d, water_mark count: %d, "
            "should allocate: %d trunks", __LINE__, allocator->
            path_info->store.path.str, allocator->freelist.count,
            allocator->freelist.water_mark_trunks, count);
    for (i=0; i<count; i++) {
        trunk_maker_allocate(allocator);
    }
}

void trunk_freelist_add(DATrunkFreelist *freelist,
        DATrunkFileInfo *trunk_info)
{
    int64_t avail_bytes;

    PTHREAD_MUTEX_LOCK(&freelist->lcp.lock);
    trunk_info->alloc.next = NULL;
    if (freelist->head == NULL) {
        freelist->head = trunk_info;
    } else {
        freelist->tail->alloc.next = trunk_info;
    }
    freelist->tail = trunk_info;

    freelist->count++;
    da_set_trunk_status(trunk_info, DA_TRUNK_STATUS_ALLOCING);
    avail_bytes = DA_TRUNK_AVAIL_SPACE(trunk_info);
    PTHREAD_MUTEX_UNLOCK(&freelist->lcp.lock);

    __sync_add_and_fetch(&trunk_info->allocator->path_info->
            trunk_stat.avail, avail_bytes);
}

static void trunk_freelist_remove(DATrunkFreelist *freelist)
{
    DATrunkFileInfo *trunk_info;

    trunk_info = freelist->head;
    freelist->head = freelist->head->alloc.next;
    if (freelist->head == NULL) {
        freelist->tail = NULL;
    }
    freelist->count--;

    da_set_trunk_status(trunk_info, DA_TRUNK_STATUS_REPUSH);
    push_trunk_util_event_force(trunk_info->allocator,
            trunk_info, DA_TRUNK_UTIL_EVENT_CREATE);
    da_set_trunk_status(trunk_info, DA_TRUNK_STATUS_NONE);

    if (freelist->count < freelist->water_mark_trunks) {
        trunk_maker_allocate_ex(trunk_info->allocator,
                true, false, NULL, NULL);
    }
}

static int waiting_avail_trunk(struct da_trunk_allocator *allocator,
        DATrunkFreelist *freelist)
{
    int result;
    int i;

    result = 0;
    for (i=0; i<10; i++) {
        if (allocator->allocate.creating_trunks == 0 && (g_current_time -
                    allocator->allocate.last_trigger_time > 0 || i > 0))
        {
            allocator->allocate.last_trigger_time = g_current_time;
            if ((result=trunk_maker_allocate_ex(allocator,
                            true, false, NULL, NULL)) != 0)
            {
                break;
            }
        }

        allocator->allocate.waiting_callers++;
        while (allocator->allocate.creating_trunks > 0 &&
                freelist->head == NULL && SF_G_CONTINUE_FLAG)
        {
            pthread_cond_wait(&freelist->lcp.cond,
                    &freelist->lcp.lock);
        }
        allocator->allocate.waiting_callers--;

        if (freelist->head != NULL || allocator->reclaim.last_errno != 0) {
            break;
        }
    }

    return result;
}

int trunk_freelist_alloc_space(struct da_trunk_allocator *allocator,
        DATrunkFreelist *freelist, const uint64_t blk_hc, const int size,
        DATrunkSpaceInfo *spaces, int *count, const bool is_normal)
{
    int result;
    uint32_t aligned_size;
    uint32_t remain_bytes;
    DATrunkSpaceInfo *space_info;
    DATrunkFileInfo *trunk_info;

    aligned_size = MEM_ALIGN_CEIL(size, DA_SPACE_ALIGN_SIZE);
    space_info = spaces;

    PTHREAD_MUTEX_LOCK(&freelist->lcp.lock);
    do {
        if (freelist->head != NULL) {
            trunk_info = freelist->head;
            remain_bytes = DA_TRUNK_AVAIL_SPACE(trunk_info);
            if (remain_bytes < aligned_size) {
                if (!is_normal && freelist->count <= 1) {
                    result = EAGAIN;
                    break;
                }
                
                if (remain_bytes <= 0) {
                    logInfo("allocator: %p, trunk_info: %p, "
                            "trunk size: %u, free start: %u, "
                            "remain_bytes: %u", trunk_info->allocator,
                            trunk_info, trunk_info->size,
                            trunk_info->free_start, remain_bytes);
                    abort();
                }

                if (*count >= 2) {
                    TRUNK_ALLOC_SPACE(trunk_info, space_info, remain_bytes);
                    space_info++;
                    aligned_size -= remain_bytes;
                }

                trunk_freelist_remove(freelist);
            }
        }

        if (freelist->head == NULL) {
            if (!is_normal) {
                result = EAGAIN;
                break;
            }

            if ((result=waiting_avail_trunk(allocator, freelist)) != 0) {
                break;
            }
        }

        if (freelist->head == NULL) {
            result = SF_G_CONTINUE_FLAG ? ENOSPC : EINTR;
            break;
        }

        trunk_info = freelist->head;
        if (aligned_size > DA_TRUNK_AVAIL_SPACE(trunk_info)) {
            result = EAGAIN;
            break;
        }

        TRUNK_ALLOC_SPACE(trunk_info, space_info, aligned_size);
        space_info++;
        if (DA_TRUNK_AVAIL_SPACE(trunk_info) <
                DA_STORE_CFG.discard_remain_space_size)
        {
            trunk_freelist_remove(freelist);
            __sync_sub_and_fetch(&trunk_info->allocator->path_info->
                    trunk_stat.avail, DA_TRUNK_AVAIL_SPACE(trunk_info));
        }

        result = 0;
        *count = space_info - spaces;
    } while (0);

    if (result == ENOSPC && is_normal) {
        da_remove_from_avail_aptr_array(&g_allocator_mgr->
                store_path, allocator);
    }
    PTHREAD_MUTEX_UNLOCK(&freelist->lcp.lock);

    return result;
}
