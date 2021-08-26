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

#ifndef _BINLOG_TYPES_H
#define _BINLOG_TYPES_H

#include "fastcommon/common_define.h"
#include "fastcommon/fc_list.h"
#include "sf/sf_types.h"

#define DA_BINLOG_RECORD_MAX_SIZE  128

typedef struct da_binlog_id_type_pair {
    uint64_t id;
    int type;
} DABinlogIdTypePair;

typedef enum da_binlog_op_type {
    inode_index_op_type_log = 'l',
    inode_index_op_type_synchronize = 's'
} DABinlogOpType;

typedef struct da_binlog_writer {
    DABinlogIdTypePair key;
    volatile int updating_count;
} DABinlogWriter;

typedef struct da_binlog_record {
    DABinlogWriter *writer;
    DABinlogOpType op_type;
    int64_t version;  //for stable sort
    void *args;
    struct da_binlog_record *next;  //for queue
} DABinlogRecord;

typedef int (*da_binlog_pack_record_func)(void *args,
        char *buff, const int size);

typedef int (*da_binlog_unpack_record_func)(const string_t *line,
        void *args, char *error_info);

typedef int (*da_binlog_batch_update_func)(DABinlogWriter *writer,
            DABinlogRecord **records, const int count);

#define DA_BINLOG_ID_TYPE_EQUALS(key1, key2) \
    ((key1).id == (key2).id && (key1).type == (key2).type)

#endif
