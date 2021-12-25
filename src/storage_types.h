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


#ifndef _DA_STORAGE_TYPES_H
#define _DA_STORAGE_TYPES_H

#include "fastcommon/fc_list.h"
#include "fastcommon/shared_buffer.h"
#include "fastcommon/uniq_skiplist.h"
#include "sf/sf_types.h"
#include "binlog/common/binlog_types.h"

#ifdef OS_LINUX
#include "dio/read_buffer_pool.h"
#endif

#define DA_SPACE_ALIGN_SIZE  8
#define DA_TRUNK_BINLOG_MAX_RECORD_SIZE    128
#define DA_TRUNK_BINLOG_SUBDIR_NAME      "trunk"

#define DA_DEFAULT_TRUNK_FILE_SIZE  (256 * 1024 * 1024LL)
#define DA_TRUNK_FILE_MIN_SIZE      ( 64 * 1024 * 1024LL)
#define DA_TRUNK_FILE_MAX_SIZE      (  2 * 1024 * 1024 * 1024LL)

#define DA_DEFAULT_DISCARD_REMAIN_SPACE_SIZE  4096
#define DA_DISCARD_REMAIN_SPACE_MIN_SIZE       256
#define DA_DISCARD_REMAIN_SPACE_MAX_SIZE      (256 * 1024)

#define DA_MAX_SPLIT_COUNT_PER_SPACE_ALLOC   2
#define DA_SLICE_SN_PARRAY_INIT_ALLOC_COUNT  4

#define DA_FIELD_UPDATE_SOURCE_NORMAL   'N'
#define DA_FIELD_UPDATE_SOURCE_RECLAIM  'R'

#define DA_REDO_QUEUE_PUSH_FLAGS_SKIP    1 //do NOT need migrate
#define DA_REDO_QUEUE_PUSH_FLAGS_IGNORE  2 //object/inode not exist

struct da_slice_op_context;
struct da_trunk_allocator;
struct da_piece_field_info;

typedef void (*da_rw_done_callback_func)(
        struct da_slice_op_context *op_ctx, void *arg);

typedef int (*da_redo_queue_push_func)(const struct da_piece_field_info
        *field, struct fc_queue_info *space_chain,
        SFSynchronizeContext *sctx, int *flags);

typedef struct {
    int index;   //the inner index is important!
    string_t path;
} DAStorePath;

typedef struct {
    uint32_t id;
    uint32_t subdir;     //in which subdir
} DATrunkIdInfo;

typedef struct {
    DAStorePath *store;
    DATrunkIdInfo id_info;
    uint32_t offset;  //offset of the trunk file
    uint32_t size;    //alloced space size
} DATrunkSpaceInfo;

#ifdef OS_LINUX
typedef struct aio_buffer_ptr_array {
    int alloc;
    int count;
    struct aligned_read_buffer **buffers;
} AIOBufferPtrArray;

typedef enum {
    da_buffer_type_direct,  /* char *buff */
    da_buffer_type_array    /* aligned_read_buffer **array */
} DAIOBufferType;
#endif

typedef struct da_trunk_file_info {
    struct da_trunk_allocator *allocator;
    DATrunkIdInfo id_info;
    volatile int status;
    struct {
        uint32_t count;  //slice count
        volatile uint32_t bytes;
    } used;
    uint32_t size;        //file size
    uint32_t free_start;  //free space offset

    struct {
        struct da_trunk_file_info *next;
    } alloc;  //for space allocate

    struct {
        struct da_trunk_file_info *next;
    } htable;  //for hashtable

    struct {
        volatile char event;
        uint32_t last_used_bytes;
        struct da_trunk_file_info *next;
    } util;  //for util manager queue
} DATrunkFileInfo;

#define DA_PIECE_FIELD_IS_EMPTY(field)  ((field)->trunk_id == 0)
#define DA_PIECE_FIELD_SET_EMPTY(field) (field)->trunk_id = 0
#define DA_PIECE_FIELD_DELETE(field)   \
    (field)->trunk_id = 0; (field)->length = 0; \
    (field)->offset = 0; (field)->size = 0

typedef struct da_piece_field_storage {
    int64_t version;
    uint32_t trunk_id; //0 for not inited
    uint32_t length;   //data length
    uint32_t offset;   //space offset
    uint32_t size;     //space size
} DAPieceFieldStorage;

typedef struct da_piece_field_info {
    uint64_t oid;
    unsigned char fid;  //filed ID (key)
    unsigned char source;
    DABinlogOpType op_type;
    DAPieceFieldStorage storage;
} DAPieceFieldInfo;

typedef struct da_piece_field_array {
    DAPieceFieldInfo *records;
    int count;
} DAPieceFieldArray;

typedef struct da_trunk_space_log_record {
    int64_t oid;        //object ID
    unsigned char fid;  //filed ID (key)
    char op_type;
    DAPieceFieldStorage storage;
    struct fast_mblock_man *allocator;
    struct da_trunk_space_log_record *next;
} DATrunkSpaceLogRecord;

typedef struct da_trunk_index_record {
    int64_t version;  //for check dirty
    uint32_t trunk_id;
    uint32_t used_count;
    uint32_t used_bytes;
    uint32_t free_start;
} DATrunkIndexRecord;

typedef struct da_trunk_read_buffer {
#ifdef OS_LINUX
    union {
        AlignedReadBuffer *aio_buffer;   //NULL for alloc from pool
        BufferInfo buffer;
    };
#else
    BufferInfo buffer;
#endif
} DATrunkReadBuffer;

typedef struct da_slice_op_context {
    DAPieceFieldStorage *storage;
    DATrunkReadBuffer rb;
} DASliceOpContext;

#ifdef OS_LINUX
#define DA_OP_CTX_BUFFER_PTR(op_ctx) (DA_READ_BY_DIRECT_IO ?      \
        (op_ctx).rb.aio_buffer->buff + (op_ctx).rb.aio_buffer->offset : \
        (op_ctx).rb.buffer.buff)
#define DA_OP_CTX_BUFFER_LEN(op_ctx) (DA_READ_BY_DIRECT_IO ?  \
        (op_ctx).rb.aio_buffer->length : (op_ctx).rb.buffer.length)
#else
#define DA_OP_CTX_BUFFER_PTR(op_ctx) (op_ctx).rb.buffer.buff
#define DA_OP_CTX_BUFFER_LEN(op_ctx) (op_ctx).rb.buffer.length
#endif


#endif
