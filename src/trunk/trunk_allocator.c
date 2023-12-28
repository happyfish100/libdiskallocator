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
#include <sys/stat.h>
#include <sys/statvfs.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/sched_thread.h"
#include "sf/sf_global.h"
#include "../binlog/common/binlog_types.h"
#include "../storage_allocator.h"
#include "trunk_hashtable.h"
#include "trunk_maker.h"
#include "trunk_allocator.h"

static int compare_trunk_by_id(const DATrunkFileInfo *t1,
        const DATrunkFileInfo *t2)
{
    return fc_compare_int64(t1->id_info.id, t2->id_info.id);
}

static int compare_trunk_by_size_id(const DATrunkFileInfo *t1,
        const DATrunkFileInfo *t2)
{
    return da_compare_trunk_by_size_id(t1, t2->util.
            last_used_bytes, t2->id_info.id);
}

static void trunk_free_func(UniqSkiplist *sl,
        void *ptr, const int delay_seconds)
{
    DATrunkFileInfo *trunk_info;
    trunk_info = (DATrunkFileInfo *)ptr;

    if (delay_seconds > 0) {
        fast_mblock_delay_free_object(&DA_TRUNK_ALLOCATOR, trunk_info,
                delay_seconds);
    } else {
        fast_mblock_free_object(&DA_TRUNK_ALLOCATOR, trunk_info);
    }
}

static inline void push_trunk_util_change_event(DATrunkAllocator *allocator,
        DATrunkFileInfo *trunk, const int event)
{
    if (__sync_bool_compare_and_swap(&trunk->util.event,
                DA_TRUNK_UTIL_EVENT_NONE, event))
    {
        fc_queue_push(&allocator->reclaim.queue, trunk);
    }
}

int da_trunk_allocator_init_instance(DATrunkAllocator *allocator,
        DAStoragePathInfo *path_info)
{
    const int min_alloc_elements_once = 4;
    const int delay_free_seconds = 0;
    const bool bidirection = true;
    int result;

    if ((result=da_trunk_freelist_init(&allocator->freelist)) != 0) {
        return result;
    }

    if ((result=uniq_skiplist_init_pair(&allocator->trunks.by_id,
                    DA_TRUNK_SKIPLIST_INIT_LEVEL_COUNT,
                    DA_TRUNK_SKIPLIST_MAX_LEVEL_COUNT,
                    (skiplist_compare_func)compare_trunk_by_id,
                    trunk_free_func, min_alloc_elements_once,
                    DA_TRUNK_SKIPLIST_DELAY_FREE_SECONDS)) != 0)
    {
        return result;
    }

    if ((result=uniq_skiplist_init_pair_ex(&allocator->trunks.by_size,
                    DA_TRUNK_SKIPLIST_INIT_LEVEL_COUNT,
                    DA_TRUNK_SKIPLIST_MAX_LEVEL_COUNT, (skiplist_compare_func)
                    compare_trunk_by_size_id, NULL, min_alloc_elements_once,
                    delay_free_seconds, bidirection)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&allocator->reclaim.queue, (long)
                    (&((DATrunkFileInfo *)NULL)->util.next))) != 0)
    {
        return result;
    }

    allocator->path_info = path_info;
    return 0;
}

int da_trunk_allocator_add(DATrunkAllocator *allocator,
        const DATrunkIdInfo *id_info, const int64_t size,
        DATrunkFileInfo **pp_trunk)
{
    DATrunkFileInfo *trunk_info;
    int result;

    trunk_info = (DATrunkFileInfo *)fast_mblock_alloc_object(
            &DA_TRUNK_ALLOCATOR);
    if (trunk_info == NULL) {
        if (pp_trunk != NULL) {
            *pp_trunk = NULL;
        }
        return ENOMEM;
    }

    da_set_trunk_status(trunk_info, DA_TRUNK_STATUS_NONE);

    PTHREAD_MUTEX_LOCK(&allocator->freelist.lcp.lock);
    trunk_info->allocator = allocator;
    trunk_info->id_info = *id_info;
    trunk_info->size = size;
    trunk_info->used.bytes = 0;
    trunk_info->used.count = 0;
    trunk_info->free_start = 0;
    trunk_info->start_version = 0;
    trunk_info->writing_count = 0;
    result = uniq_skiplist_insert(allocator->
            trunks.by_id.skiplist, trunk_info);
    PTHREAD_MUTEX_UNLOCK(&allocator->freelist.lcp.lock);

    if (result == 0) {
        result = da_trunk_hashtable_add(&allocator->path_info->
                ctx->trunk_htable_ctx, trunk_info);
    } 

    if (result != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "add trunk fail, trunk id: %"PRId64", "
                "errno: %d, error info: %s", __LINE__,
                allocator->path_info->ctx->module_name,
                id_info->id, result, STRERROR(result));
        fast_mblock_free_object(&DA_TRUNK_ALLOCATOR, trunk_info);
        trunk_info = NULL;
    }
    if (pp_trunk != NULL) {
        *pp_trunk = trunk_info;
    }
    return result;
}

int da_trunk_allocator_delete(DATrunkAllocator *allocator, const uint64_t id)
{
    DATrunkFileInfo target;
    int result;

    target.id_info.id = id;
    PTHREAD_MUTEX_LOCK(&allocator->freelist.lcp.lock);
    result = uniq_skiplist_delete(allocator->trunks.by_id.skiplist, &target);
    PTHREAD_MUTEX_UNLOCK(&allocator->freelist.lcp.lock);

    return result;
}

int da_trunk_allocator_deal_space_changes(DAContext *ctx,
        DATrunkFileInfo *trunk, DATrunkSpaceLogRecord **records,
        const int count)
{
    DATrunkSpaceLogRecord **record;
    DATrunkSpaceLogRecord **end;
    int64_t changed_bytes;
    int64_t positive_bytes;

    if (count <= 0) {
        return 0;
    }

    changed_bytes = 0;
    end = records + count;
    PTHREAD_MUTEX_LOCK(&trunk->allocator->freelist.lcp.lock);
    for (record=records; record<end; record++) {
        if ((*record)->op_type == da_binlog_op_type_consume_space) {
            changed_bytes += (*record)->storage.size;
            trunk->used.count++;
        } else {
            changed_bytes -= (*record)->storage.size;
            trunk->used.count--;
        }
    }
    trunk->update_time = g_current_time;
    PTHREAD_MUTEX_UNLOCK(&trunk->allocator->freelist.lcp.lock);

    if (changed_bytes > 0) {
        __sync_add_and_fetch(&trunk->used.bytes, changed_bytes);
        __sync_add_and_fetch(&trunk->allocator->path_info->
                trunk_stat.used, changed_bytes);
    } else {
        positive_bytes = -1 * changed_bytes;
        __sync_sub_and_fetch(&trunk->used.bytes, positive_bytes);
        __sync_sub_and_fetch(&trunk->allocator->path_info->
                trunk_stat.used, positive_bytes);
        push_trunk_util_change_event(trunk->allocator, trunk,
                DA_TRUNK_UTIL_EVENT_UPDATE);
    }

    return 0;
}

DATrunkFreelistType da_trunk_allocator_add_to_freelist(
        DATrunkAllocator *allocator, DATrunkFileInfo *trunk_info)
{
    struct da_storage_allocator_manager *allocator_mgr;
    DATrunkFreelist *freelist;

    allocator_mgr = allocator->path_info->ctx->store_allocator_mgr;
    PTHREAD_MUTEX_LOCK(&allocator_mgr->reclaim_freelist.lcp.lock);
    if (allocator_mgr->reclaim_freelist.count < allocator_mgr->
            reclaim_freelist.water_mark_trunks)
    {
        freelist = &allocator_mgr->reclaim_freelist;
    } else {
        freelist = &allocator->freelist;
    }
    PTHREAD_MUTEX_UNLOCK(&allocator_mgr->reclaim_freelist.lcp.lock);

    da_trunk_freelist_add(freelist, trunk_info);
    return (freelist == &allocator->freelist) ? da_freelist_type_normal :
        da_freelist_type_reclaim;
}

static bool can_add_to_freelist(DATrunkFileInfo *trunk_info)
{
    int64_t remain_size;
    double ratio_thredhold;

    /*
    logInfo("file: "__FILE__", line: %d, %s"
            "path index: %d, trunk id: %"PRId64", "
            "used bytes: %"PRId64", free start: %u", __LINE__,
            trunk_info->allocator->path_info->ctx->module_name,
            trunk_info->allocator->path_info->store.index,
            trunk_info->id_info.id, trunk_info->used.bytes,
            trunk_info->free_start);
            */

    if (trunk_info->free_start == 0) {
        return true;
    } else if (trunk_info->used.bytes == 0) {
        trunk_info->free_start = 0;
        return true;
    }

    remain_size = DA_TRUNK_AVAIL_SPACE(trunk_info);
    if (remain_size < trunk_info->allocator->path_info->
            ctx->storage.file_block_size)
    {
        return false;
    }

    if (trunk_info->allocator->path_info->space_stat.used_ratio <=
            trunk_info->allocator->path_info->ctx->storage.cfg.
            reclaim_trunks_on_path_usage)
    {
        return ((double)trunk_info->free_start / (double)trunk_info->size
                <= (1.00 -  trunk_info->allocator->path_info->
                    ctx->storage.cfg.reclaim_trunks_on_path_usage));
    }

    if ((double)remain_size / (double)trunk_info->size >=
            (1.00 - trunk_info->allocator->path_info->
             ctx->storage.cfg.reclaim_trunks_on_path_usage))
    {
        return true;
    }

    ratio_thredhold = da_trunk_allocator_calc_reclaim_ratio_thredhold(
            trunk_info->allocator);
    return ((double)trunk_info->used.bytes / (double)
            trunk_info->free_start > ratio_thredhold);
}

void da_trunk_allocator_deal_on_ready(DATrunkAllocator *allocator)
{
    UniqSkiplistIterator it;
    DATrunkFileInfo *trunk_info;

    uniq_skiplist_iterator(allocator->trunks.by_id.skiplist, &it);
    while ((trunk_info=uniq_skiplist_next(&it)) != NULL) {
        allocator->path_info->trunk_stat.total += trunk_info->size;
        allocator->path_info->trunk_stat.used += trunk_info->used.bytes;

        if (can_add_to_freelist(trunk_info)) {
            if (trunk_info->free_start == 0) { //whole trunk is available
                da_trunk_allocator_add_to_freelist(allocator, trunk_info);
            } else {
                da_trunk_freelist_add(&allocator->freelist, trunk_info);
            }
        } else {
            push_trunk_util_change_event(allocator, trunk_info,
                    DA_TRUNK_UTIL_EVENT_CREATE);
        }

        //da_trunk_allocator_log_trunk_info(trunk_info);
    }
}

void da_trunk_allocator_log_trunk_info(DATrunkFileInfo *trunk_info)
{
    logInfo("%s trunk id: %"PRId64", path index: %d, subdir: %u, "
            "status: %d, slice count: %d, used bytes: %"PRId64", "
            "trunk size: %u, free start: %u, remain bytes: %"PRId64,
            trunk_info->allocator->path_info->ctx->module_name,
            trunk_info->id_info.id, trunk_info->allocator->path_info->
            store.index, trunk_info->id_info.subdir, trunk_info->status,
            trunk_info->used.count, trunk_info->used.bytes,
            trunk_info->size, trunk_info->free_start,
            DA_TRUNK_AVAIL_SPACE(trunk_info));
}
