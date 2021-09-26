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


#ifndef _STORAGE_TYPES_H
#define _STORAGE_TYPES_H

#include "fastcommon/fc_list.h"
#include "fastcommon/shared_buffer.h"
#include "fastcommon/uniq_skiplist.h"
#include "sf/sf_types.h"

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

struct da_trunk_allocator;

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

typedef struct {
    DATrunkSpaceInfo space;
    int64_t version; //for write in order
} DATrunkSpaceWithVersion;

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
        int count;  //slice count
        volatile uint32_t bytes;
    } used;
    uint32_t size;        //file size
    uint32_t free_start;  //free space offset

    struct {
        struct da_trunk_file_info *next;
    } alloc;  //for space allocate

    struct {
        volatile char event;
        uint32_t last_used_bytes;
        struct da_trunk_file_info *next;
    } util;  //for util manager queue
} DATrunkFileInfo;

#endif
