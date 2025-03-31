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


#ifndef _DA_TRUNK_DEFRAG_H
#define _DA_TRUNK_DEFRAG_H

#include "fastcommon/fc_queue.h"
#include "fastcommon/uniq_skiplist.h"
#include "../storage_config.h"
#include "../binlog/trunk/space_log_reader.h"
#include "../dio/trunk_read_thread.h"
#include "trunk_allocator.h"

struct da_trunk_defrag_context;
typedef struct da_trunk_defrag_block_info {
    DATrunkSpaceLogRecord *head;
    int total_length;
} DATrunkDefragBlockInfo;

typedef struct da_trunk_defrag_block_array {
    int count;
    int alloc;
    DATrunkDefragBlockInfo *blocks;
} DATrunkDefragBlockArray;

typedef struct da_trunk_defrag_thread {
    DASpaceLogReader reader;
    UniqSkiplist *skiplist;
    DATrunkDefragBlockArray barray;
    int index;
    struct {
        int total;
        int merged;
        int skip;   //do NOT need migrate
        int ignore; //object/inode not exist
    } slice_counts;
    SFSynchronizeContext log_notify;  //for binlog
    struct fc_queue queue;
    struct da_trunk_defrag_context *ctx;
} DATrunkDefragThread;

typedef struct {
    DATrunkDefragThread *threads;
    int count;
} DATrunkDefragThreadArray;

typedef struct da_trunk_defrag_context {
    DAContext *da_ctx;
    volatile int running_count;
    DATrunkDefragThreadArray thread_array;
} DATrunkDefragContext;

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_defrag_init(DAContext *ctx);

    void da_trunk_defrag_check_push(DATrunkFileInfo *trunk);

#ifdef __cplusplus
}
#endif

#endif
