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
#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fc_memory.h"
#include "sf/sf_global.h"
#include "binlog/trunk/trunk_space_log.h"
#include "global.h"
#include "trunk/trunk_maker.h"
#include "storage_allocator.h"

static int check_trunk_avail_func(void *args);

static int init_allocator_context(DAContext *ctx,
        DAStorageAllocatorContext *allocator_ctx,
        DAStoragePathArray *parray)
{
    int result;
    int bytes;
    DAStoragePathInfo *path;
    DAStoragePathInfo *end;
    DATrunkAllocator *pallocator;

    if (parray->count == 0) {
        return 0;
    }

    bytes = sizeof(DATrunkAllocator) * parray->count;
    allocator_ctx->all.allocators = (DATrunkAllocator *)fc_malloc(bytes);
    if (allocator_ctx->all.allocators == NULL) {
        return ENOMEM;
    }
    memset(allocator_ctx->all.allocators, 0, bytes);

    end = parray->paths + parray->count;
    for (path=parray->paths,pallocator=allocator_ctx->all.allocators;
            path<end; path++, pallocator++)
    {
        if ((result=da_trunk_allocator_init_instance(pallocator, path)) != 0) {
            return result;
        }

        ctx->store_allocator_mgr->allocator_ptr_array.allocators
            [path->store.index] = pallocator;
    }
    allocator_ctx->all.count = parray->count;
    return 0;
}

static int aptr_array_alloc_init(void *element, void *args)
{
    DATrunkAllocatorPtrArray *aptr_array;
    aptr_array = (DATrunkAllocatorPtrArray *)element;
    aptr_array->allocators = (DATrunkAllocator **)(aptr_array + 1);
    aptr_array->alloc = (long)args;
    return 0;
}

int da_storage_allocator_init(DAContext *ctx)
{
    int result;
    int bytes;
    int count;
    int element_size;


    count = ctx->storage.cfg.max_store_path_index + 1;
    bytes = sizeof(DAStorageAllocatorManager) +
        sizeof(DATrunkAllocator *) * count;
    ctx->store_allocator_mgr = fc_malloc(bytes);
    if (ctx->store_allocator_mgr == NULL) {
        return ENOMEM;
    }
    memset(ctx->store_allocator_mgr, 0, bytes);
    ctx->store_allocator_mgr->allocator_ptr_array.count = count;
    ctx->store_allocator_mgr->allocator_ptr_array.allocators =
        (DATrunkAllocator **)(ctx->store_allocator_mgr + 1);

    if ((result=init_pthread_lock(&ctx->store_allocator_mgr->lock)) != 0) {
        return result;
    }

    if ((result=da_trunk_freelist_init(&ctx->store_allocator_mgr->
                    reclaim_freelist)) != 0)
    {
        return result;
    }

    if ((result=init_allocator_context(ctx, &ctx->store_allocator_mgr->
                    write_cache, &ctx->storage.cfg.write_cache)) != 0)
    {
        return result;
    }
    if ((result=init_allocator_context(ctx, &ctx->store_allocator_mgr->
                    store_path, &ctx->storage.cfg.store_path)) != 0)
    {
        return result;
    }

    count = FC_MAX(ctx->store_allocator_mgr->write_cache.all.count,
            ctx->store_allocator_mgr->store_path.all.count);
    element_size = sizeof(DATrunkAllocatorPtrArray) +
        sizeof(DATrunkAllocator *) * count;
    if ((result=fast_mblock_init_ex1(&ctx->store_allocator_mgr->aptr_array_allocator,
                    "aptr_array", element_size, 64, 0, aptr_array_alloc_init,
                    (void *)(long)count, true)) != 0)
    {
        return result;
    }

    return da_trunk_id_info_init(ctx);
}

static int deal_allocator_on_ready(DAContext *ctx,
        DAStorageAllocatorContext *allocator_ctx)
{
    DATrunkAllocator *allocator;
    DATrunkAllocator *end;
    char total_buff[32];
    char used_buff[32];
    char avail_buff[32];

    end = allocator_ctx->all.allocators + allocator_ctx->all.count;
    for (allocator=allocator_ctx->all.allocators; allocator<end; allocator++) {
        da_trunk_allocator_deal_on_ready(allocator);

        long_to_comma_str(allocator->path_info->trunk_stat.total /
                (1024 * 1024), total_buff);
        long_to_comma_str(allocator->path_info->trunk_stat.used /
                (1024 * 1024), used_buff);
        long_to_comma_str(allocator->path_info->trunk_stat.avail /
                (1024 * 1024), avail_buff);
        logInfo("%s path #%d: %s, trunk count: %d, space stats "
                "{total: %s MB, used: %s MB, avail: %s MB}", ctx->module_name,
                allocator->path_info->store.index,
                allocator->path_info->store.path.str,
                uniq_skiplist_count(allocator->trunks.by_id.skiplist),
                total_buff, used_buff, avail_buff);
    }

    return 0;
}

static int prealloc_trunk_freelist(DAStorageAllocatorContext *allocator_ctx)
{
    DATrunkAllocator *allocator;
    DATrunkAllocator *end;

    end = allocator_ctx->all.allocators + allocator_ctx->all.count;
    for (allocator=allocator_ctx->all.allocators; allocator<end; allocator++) {
        da_trunk_freelist_keep_water_mark(allocator);
    }

    return 0;
}

static void wait_allocator_available(DAContext *ctx)
{
    DATrunkAllocatorPtrArray *avail_array;
    int count;
    int i;

    i = 0;
    while (ctx->store_allocator_mgr->store_path.full->count > 0 && i < 10) {
        fc_sleep_ms(100);
        if (i % 5 == 0) {
            check_trunk_avail_func(ctx);
        }
        ++i;
    }

    i = 0;
    while (ctx->store_allocator_mgr->store_path.
            avail->count == 0 && i++ < 10)
    {
        fc_sleep_ms(100);
    }

    logInfo("file: "__FILE__", line: %d, %s "
            "waiting count: %d, path stat {avail count: %d, "
            "full count: %d}, freelist for reclaim count: %d", __LINE__,
            ctx->module_name, i, ctx->store_allocator_mgr->store_path.
            avail->count, ctx->store_allocator_mgr->store_path.full->count,
            ctx->store_allocator_mgr->reclaim_freelist.count);

    count = ctx->store_allocator_mgr->reclaim_freelist.water_mark_trunks -
        ctx->store_allocator_mgr->reclaim_freelist.count;
    if (count <= 0) {
        return;
    }

    avail_array = (DATrunkAllocatorPtrArray *)
        ctx->store_allocator_mgr->store_path.avail;
    for (i=0; i<avail_array->count; i++) {
        da_trunk_maker_allocate_ex(avail_array->allocators[i],
                true, true, NULL, NULL);
    }
}

#define CMP_APTR_BY_PINDEX(a1, a2) \
    ((int)(a1)->path_info->store.index - \
     (int)(a2)->path_info->store.index)

static int compare_allocator_by_path_index(
        DATrunkAllocator **pp1,
        DATrunkAllocator **pp2)
{
    return CMP_APTR_BY_PINDEX(*pp1, *pp2);
}

static inline int add_to_aptr_array(DATrunkAllocatorPtrArray
        *aptr_array, DATrunkAllocator *allocator)
{
    DATrunkAllocator **pos;
    DATrunkAllocator **end;
    int r;

    end = aptr_array->allocators + aptr_array->count;
    for (pos=aptr_array->allocators; pos<end; pos++) {
        r = CMP_APTR_BY_PINDEX(allocator, *pos);
        if (r < 0) {
            break;
        } else if (r == 0) {
            return EEXIST;
        }
    }

    if (aptr_array->count >= aptr_array->alloc) {
        return ENOSPC;
    }

    if (pos < end) {
        DATrunkAllocator **pp;

        for (pp=end; pp>pos; pp--) {
            *pp = *(pp - 1);
        }
    }

    *pos = allocator;
    aptr_array->count++;
    return 0;
}

static inline int remove_from_aptr_array(DATrunkAllocatorPtrArray *aptr_array,
        DATrunkAllocator *allocator)
{
    DATrunkAllocator **pp;
    DATrunkAllocator **end;

    end = aptr_array->allocators + aptr_array->count;
    for (pp=aptr_array->allocators; pp<end; pp++) {
        if (CMP_APTR_BY_PINDEX(*pp, allocator) == 0) {
            break;
        }
    }
    if (pp == end) {
        return ENOENT;
    }

    for (pp=pp+1; pp<end; pp++) {
        *(pp - 1) = *pp;
    }
    aptr_array->count--;
    return 0;
}

int init_allocator_ptr_array(DAContext *ctx,
        DAStorageAllocatorContext *allocator_ctx)
{
    DATrunkAllocator *allocator;
    DATrunkAllocator *end;
    DATrunkAllocatorPtrArray *aptr_array;

    allocator_ctx->full = (DATrunkAllocatorPtrArray *)
        fast_mblock_alloc_object(&ctx->store_allocator_mgr->aptr_array_allocator);
    if (allocator_ctx->full == NULL) {
        return ENOMEM;
    }

    allocator_ctx->avail = (DATrunkAllocatorPtrArray *)
        fast_mblock_alloc_object(&ctx->store_allocator_mgr->aptr_array_allocator);
    if (allocator_ctx->avail == NULL) {
        return ENOMEM;
    }

    allocator_ctx->full->count = allocator_ctx->avail->count = 0;
    end = allocator_ctx->all.allocators + allocator_ctx->all.count;
    for (allocator=allocator_ctx->all.allocators; allocator<end; allocator++) {
        if (da_trunk_allocator_is_available(allocator)) {
            aptr_array = (DATrunkAllocatorPtrArray *)allocator_ctx->avail;
        } else {
            /* for trigger check trunk avail */
            allocator->path_info->trunk_stat.last_used =
                FC_ATOMIC_GET(allocator->path_info->trunk_stat.used) +
                ctx->storage.cfg.trunk_file_size;
            aptr_array = (DATrunkAllocatorPtrArray *)allocator_ctx->full;
        }
        add_to_aptr_array(aptr_array, allocator);

        /*
        logInfo("%s path index: %d, avail count: %d, full count: %d",
                ctx->module_name, allocator->path_info->store.index,
                allocator_ctx->avail->count,
                allocator_ctx->full->count);
                */
    }

    return 0;
}

static int check_trunk_avail(DAContext *ctx,
        DAStorageAllocatorContext *allocator_ctx)
{
    DATrunkAllocatorPtrArray *aptr_array;
    DATrunkAllocator **pp;
    DATrunkAllocator **end;
    int64_t used_bytes;
    int r;
    int result;

    result = 0;
    aptr_array = (DATrunkAllocatorPtrArray *)allocator_ctx->full;
    end = aptr_array->allocators + aptr_array->count;
    for (pp=aptr_array->allocators; pp<end; pp++) {
        if (da_trunk_allocator_is_available(*pp)) {
            if ((r=da_add_to_avail_aptr_array(ctx,
                            allocator_ctx, *pp)) != 0)
            {
                result = r;
            }
        } else {
            used_bytes = FC_ATOMIC_GET((*pp)->path_info->trunk_stat.used);
            if ((*pp)->path_info->trunk_stat.last_used - used_bytes >=
                    ctx->storage.cfg.trunk_file_size)
            {
                (*pp)->path_info->trunk_stat.last_used = used_bytes;
                da_trunk_maker_allocate_ex(*pp, true, true, NULL, NULL);
            } else {
                da_storage_config_calc_path_avail_space((*pp)->path_info);
                if ((*pp)->path_info->space_stat.avail - ctx->storage.cfg.
                        trunk_file_size > (*pp)->path_info->reserved_space.value)
                {
                    da_trunk_maker_allocate(*pp);
                }
            }
        }
    }

    return result;
}

static int check_trunk_avail_func(void *args)
{
    DAContext *ctx;
    int result;

    ctx = args;
    if (ctx->check_trunk_avail_in_progress) {
        return EINPROGRESS;
    }

    ctx->check_trunk_avail_in_progress = true;
    if (ctx->store_allocator_mgr->store_path.full->count > 0) {
        logInfo("file: "__FILE__", line: %d, %s "
                "store path counts {total: %d, full: %d}",
                __LINE__, ctx->module_name,
                ctx->store_allocator_mgr->allocator_ptr_array.count,
                ctx->store_allocator_mgr->store_path.full->count);
        result = check_trunk_avail(ctx, &ctx->
                store_allocator_mgr->store_path);
    } else {
        result = 0;
    }
    ctx->check_trunk_avail_in_progress = false;
    return result;
}

static int setup_check_trunk_avail_schedule(DAContext *ctx)
{
    ScheduleArray scheduleArray;
    ScheduleEntry scheduleEntry;

    INIT_SCHEDULE_ENTRY(scheduleEntry, sched_generate_next_id(),
           TIME_NONE, TIME_NONE, TIME_NONE, 10,
            check_trunk_avail_func, ctx);
    scheduleArray.entries = &scheduleEntry;
    scheduleArray.count = 1;
    return sched_add_entries(&scheduleArray);
}

int da_storage_allocator_prealloc_trunk_freelists(DAContext *ctx)
{
    int result;

    if ((result=deal_allocator_on_ready(ctx, &ctx->
                    store_allocator_mgr->write_cache)) != 0)
    {
        return result;
    }

    if ((result=deal_allocator_on_ready(ctx, &ctx->
                    store_allocator_mgr->store_path)) != 0)
    {
        return result;
    }

    if ((result=init_allocator_ptr_array(ctx, &ctx->
                    store_allocator_mgr->write_cache)) != 0)
    {
        return result;
    }

    if ((result=init_allocator_ptr_array(ctx, &ctx->
                    store_allocator_mgr->store_path)) != 0)
    {
        return result;
    }

    logInfo("%s global freelist for reclaim {avail: %d, water_mark: %d}",
            ctx->module_name, ctx->store_allocator_mgr->
            reclaim_freelist.count, ctx->store_allocator_mgr->
            reclaim_freelist.water_mark_trunks);

    if ((result=prealloc_trunk_freelist(&ctx->store_allocator_mgr->
                    write_cache)) != 0)
    {
        return result;
    }

    if ((result=prealloc_trunk_freelist(&ctx->store_allocator_mgr->
                    store_path)) != 0)
    {
        return result;
    }

    if ((result=setup_check_trunk_avail_schedule(ctx)) != 0) {
        return result;
    }
    wait_allocator_available(ctx);
    return 0;
}

static inline DATrunkAllocatorPtrArray *duplicate_aptr_array(
        DAContext *ctx, DATrunkAllocatorPtrArray *aptr_array)
{
    DATrunkAllocatorPtrArray *new_array;

    new_array = (DATrunkAllocatorPtrArray *)fast_mblock_alloc_object(
            &ctx->store_allocator_mgr->aptr_array_allocator);
    if (new_array == NULL) {
        return NULL;
    }

    if (aptr_array->count > 0) {
        memcpy(new_array->allocators, aptr_array->allocators,
                sizeof(DATrunkAllocator *) * aptr_array->count);
    }

    new_array->count = aptr_array->count;
    return new_array;
}

static inline void switch_aptr_array(DAContext *ctx,
        DATrunkAllocatorPtrArray **aptr_array,
        DATrunkAllocatorPtrArray *new_array)
{
    DATrunkAllocatorPtrArray *old_array;

    old_array = *aptr_array;
    *aptr_array = new_array;
    fast_mblock_delay_free_object(&ctx->store_allocator_mgr->
            aptr_array_allocator, old_array, 60);
}

int da_move_allocator_ptr_array(DAContext *ctx, DATrunkAllocatorPtrArray
        **src_array, DATrunkAllocatorPtrArray **dest_array,
        DATrunkAllocator *allocator)
{
    int result;
    DATrunkAllocatorPtrArray *new_sarray;
    DATrunkAllocatorPtrArray *new_darray;

    new_sarray = new_darray = NULL;
    PTHREAD_MUTEX_LOCK(&ctx->store_allocator_mgr->lock);
    do {
        if (bsearch(&allocator, (*src_array)->allocators,
                    (*src_array)->count, sizeof(DATrunkAllocator *),
                    (int (*)(const void *, const void *))
                    compare_allocator_by_path_index) == NULL)
        {
            result = ENOENT;
            break;
        }

        if ((new_sarray=duplicate_aptr_array(ctx, *src_array)) == NULL) {
            result = ENOMEM;
            break;
        }
        if ((new_darray=duplicate_aptr_array(ctx, *dest_array)) == NULL) {
            result = ENOMEM;
            break;
        }

        if ((result=remove_from_aptr_array(new_sarray, allocator)) != 0) {
            break;
        }
        switch_aptr_array(ctx, src_array, new_sarray);
        new_sarray = NULL;

        if ((result=add_to_aptr_array(new_darray, allocator)) != 0) {
            break;
        }
        switch_aptr_array(ctx, dest_array, new_darray);
        new_darray = NULL;
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&ctx->store_allocator_mgr->lock);

    if (new_sarray != NULL) {
        fast_mblock_free_object(&ctx->store_allocator_mgr->
                aptr_array_allocator, new_sarray);
    }
    if (new_darray != NULL) {
        fast_mblock_free_object(&ctx->store_allocator_mgr->
                aptr_array_allocator, new_darray);
    }

    return result;
}

static int dump_to_array(DATrunkAllocator *allocator,
        SFBinlogIndexArray *array)
{
    UniqSkiplistIterator it;
    DATrunkFileInfo *trunk_info;
    DATrunkIndexRecord *record;
    int64_t used_bytes;
    int result;

    result = 0;
    PTHREAD_MUTEX_LOCK(&allocator->freelist.lcp.lock);
    uniq_skiplist_iterator(allocator->trunks.by_id.skiplist, &it);
    while ((trunk_info=(DATrunkFileInfo *)uniq_skiplist_next(&it)) != NULL) {
        used_bytes = FC_ATOMIC_GET(trunk_info->used.bytes);
        if (trunk_info->used.count < 0 || used_bytes < 0) {
            continue;
        }

        if (array->count >= array->alloc) {
            if ((result=sf_binlog_index_expand_array(array,
                            sizeof(DATrunkIndexRecord))) != 0)
            {
                break;
            }
        }

        record = (DATrunkIndexRecord *)array->indexes + array->count++;
        da_trunk_space_log_calc_version(allocator->path_info->ctx,
                trunk_info->id_info.id, &record->version);
        record->trunk_id = trunk_info->id_info.id;
        record->used_count = trunk_info->used.count;
        record->used_bytes = used_bytes;
        record->free_start = trunk_info->free_start;
    }
    PTHREAD_MUTEX_UNLOCK(&allocator->freelist.lcp.lock);

    return result;
}

int da_storage_allocator_trunks_to_array(DAContext *ctx,
        SFBinlogIndexArray *array)
{
    DATrunkAllocator **allocator;
    DATrunkAllocator **end;
    int result;

    array->count = 0;
    end = ctx->store_allocator_mgr->allocator_ptr_array.allocators +
        ctx->store_allocator_mgr->allocator_ptr_array.count;
    for (allocator=ctx->store_allocator_mgr->allocator_ptr_array.
            allocators; allocator<end; allocator++)
    {
        if (*allocator != NULL) {
            if ((result=dump_to_array(*allocator, array)) != 0) {
                return result;
            }
        }
    }

    return 0;
}
