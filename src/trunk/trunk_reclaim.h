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


#ifndef _TRUNK_RECLAIM_H
#define _TRUNK_RECLAIM_H

#include "fastcommon/uniq_skiplist.h"
#include "../storage_config.h"
#include "trunk_allocator.h"

typedef struct trunk_reclaim_block_info {
    DATrunkSpaceLogRecord *head;
    int total_size;
} TrunkReclaimBlockInfo;

typedef struct trunk_reclaim_block_array {
    int count;
    int alloc;
    TrunkReclaimBlockInfo *blocks;
} TrunkReclaimBlockArray;

typedef struct trunk_reclaim_context {
    struct fast_mblock_man record_allocator;
    UniqSkiplistPair spair;
    TrunkReclaimBlockArray barray;
    DASliceOpContext op_ctx;
    int buffer_size;
    SFSynchronizeContext notify;
} TrunkReclaimContext;


#ifdef __cplusplus
extern "C" {
#endif
    int trunk_reclaim_init_ctx(TrunkReclaimContext *rctx);

    int trunk_reclaim(DATrunkAllocator *allocator, DATrunkFileInfo *trunk,
            TrunkReclaimContext *rctx);

#ifdef __cplusplus
}
#endif

#endif
