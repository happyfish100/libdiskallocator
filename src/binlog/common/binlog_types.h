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

#ifndef _DA_BINLOG_TYPES_H
#define _DA_BINLOG_TYPES_H

#include "fastcommon/common_define.h"
#include "fastcommon/fc_list.h"
#include "sf/sf_types.h"

typedef struct da_binlog_id_type_pair {
    uint64_t id;
    int type;
} DABinlogIdTypePair;

#define da_binlog_op_type_consume_space  da_binlog_op_type_create
#define da_binlog_op_type_reclaim_space  da_binlog_op_type_remove

typedef enum da_binlog_op_type {
    da_binlog_op_type_create = 'c',
    da_binlog_op_type_remove = 'r',
    da_binlog_op_type_update = 'u'
} DABinlogOpType;

typedef struct da_binlog_writer {
    int type;
    int max_record_size;
    SFSynchronizeContext notify;
    struct fast_mblock_man record_allocator;
} DABinlogWriter;

typedef struct da_binlog_record {
    DABinlogIdTypePair key;
    int64_t version;  //for stable sort
    BufferInfo buffer;
    DABinlogWriter *writer;
    struct da_binlog_record *next;  //for queue
} DABinlogRecord;

typedef struct da_binlog_record_ptr_array {
    DABinlogRecord **records;
    int alloc;
    int count;
} DABinlogRecordPtrArray;

typedef int (*da_binlog_unpack_record_func)(const string_t *line,
        void *args, char *error_info);

typedef int (*da_binlog_shrink_func)(DABinlogWriter *writer, void *args);

#define DA_DECLARE_BINLOG_ID_TYPE_VAR(var, bid, tp) \
    DABinlogIdTypePair var = {bid, tp}

#define DA_SET_BINLOG_ID_TYPE(key, bid, tp) \
    (key).id = bid; (key).type = tp

#define DA_BINLOG_ID_TYPE_EQUALS(key1, key2) \
    ((key1).id == (key2).id && (key1).type == (key2).type)

#endif
