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


#ifndef _DA_TRUNK_RECLAIM_H
#define _DA_TRUNK_RECLAIM_H

#include "fastcommon/uniq_skiplist.h"
#include "../storage_config.h"
#include "../binlog/trunk/space_log_reader.h"
#include "../dio/trunk_read_thread.h"
#include "trunk_allocator.h"

typedef struct da_trunk_reclaim_block_info {
    DATrunkSpaceLogRecord *head;
    int total_size;
} DATrunkReclaimBlockInfo;

typedef struct da_trunk_reclaim_block_array {
    int count;
    int alloc;
    DATrunkReclaimBlockInfo *blocks;
} DATrunkReclaimBlockArray;

typedef struct da_trunk_reclaim_context {
    DASpaceLogReader reader;
    UniqSkiplist *skiplist;
    DATrunkReclaimBlockArray barray;
    DASynchronizedReadContext read_ctx;
    struct {
        int total;
        int skip;   //do NOT need migrate
        int ignore; //object/inode not exist
    } slice_counts;
    SFSynchronizeContext log_notify;  //for binlog
} DATrunkReclaimContext;


#ifdef __cplusplus
extern "C" {
#endif
    int da_trunk_reclaim_init_ctx(DATrunkReclaimContext *rctx);

    int da_trunk_reclaim(DATrunkAllocator *allocator, DATrunkFileInfo *trunk,
            DATrunkReclaimContext *rctx);

#ifdef __cplusplus
}
#endif

#endif
