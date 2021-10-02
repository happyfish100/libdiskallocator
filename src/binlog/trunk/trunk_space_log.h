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


#ifndef _TRUNK_SPACE_LOG_H
#define _TRUNK_SPACE_LOG_H

#include "../../storage_config.h"

typedef struct da_trunk_space_log_record_array {
    DATrunkSpaceLogRecord **records;
    int count;
    int alloc;
} DATrunkSpaceLogRecordArray;

typedef struct da_trunk_space_log_context {
    struct fc_queue queue;
    struct fast_mblock_man record_allocator;
    DATrunkSpaceLogRecordArray record_array;
    TrunkFDCacheContext fd_cache_ctx;
    FastBuffer buffer;
    time_t next_dump_time;
} DATrunkSpaceLogContext;

#ifdef __cplusplus
extern "C" {
#endif

    extern DATrunkSpaceLogContext g_trunk_space_log_ctx;

    int da_trunk_space_log_init();
    void da_trunk_space_log_destroy();

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_record()
    {
        return (DATrunkSpaceLogRecord *)fast_mblock_alloc_object(
                &g_trunk_space_log_ctx.record_allocator);
    }

    static inline int da_trunk_space_log_alloc_chain(const int count,
            struct fc_queue_info *chain)
    {
        return fc_queue_alloc_chain(&g_trunk_space_log_ctx.queue,
                &g_trunk_space_log_ctx.record_allocator, count, chain);
    }

    static inline void da_trunk_space_log_push_chain(
            struct fc_queue_info *qinfo)
    {
        fc_queue_push_queue_to_tail(&g_trunk_space_log_ctx.queue, qinfo);
    }

#ifdef __cplusplus
}
#endif

#endif
