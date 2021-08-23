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

//TODO
#define FS_FILE_BLOCK_SIZE    (4 * 1024 * 1024)

#define FS_SPACE_ALIGN_SIZE  8
#define FS_TRUNK_BINLOG_MAX_RECORD_SIZE    128
#define FS_TRUNK_BINLOG_SUBDIR_NAME      "trunk"

#define FS_DEFAULT_TRUNK_FILE_SIZE  (256 * 1024 * 1024LL)
#define FS_TRUNK_FILE_MIN_SIZE      ( 64 * 1024 * 1024LL)
#define FS_TRUNK_FILE_MAX_SIZE      (  2 * 1024 * 1024 * 1024LL)

#define FS_DEFAULT_DISCARD_REMAIN_SPACE_SIZE  4096
#define FS_DISCARD_REMAIN_SPACE_MIN_SIZE       256
#define FS_DISCARD_REMAIN_SPACE_MAX_SIZE      (256 * 1024)

#define FS_MAX_SPLIT_COUNT_PER_SPACE_ALLOC   2
#define FS_SLICE_SN_PARRAY_INIT_ALLOC_COUNT  4

struct fs_trunk_allocator;

typedef struct {
    int index;   //the inner index is important!
    string_t path;
} FSStorePath;

typedef struct {
    int64_t id;
    int64_t subdir;     //in which subdir
} FSTrunkIdInfo;

typedef struct {
    FSStorePath *store;
    FSTrunkIdInfo id_info;
    int64_t offset;  //offset of the trunk file
    int64_t size;    //alloced space size
} FSTrunkSpaceInfo;

typedef struct {
    FSTrunkSpaceInfo space;
    int64_t version; //for write in order
} FSTrunkSpaceWithVersion;

#ifdef OS_LINUX
typedef struct aio_buffer_ptr_array {
    int alloc;
    int count;
    struct aligned_read_buffer **buffers;
} AIOBufferPtrArray;

typedef enum {
    fs_buffer_type_direct,  /* char *buff */
    fs_buffer_type_array    /* aligned_read_buffer **array */
} FSIOBufferType;
#endif

typedef struct fs_trunk_file_info {
    struct fs_trunk_allocator *allocator;
    FSTrunkIdInfo id_info;
    volatile int status;
    struct {
        int count;  //slice count
        volatile int64_t bytes;
        struct fc_list_head slice_head; //OBSliceEntry double link
    } used;
    int64_t size;        //file size
    int64_t free_start;  //free space offset

    struct {
        struct fs_trunk_file_info *next;
    } alloc;  //for space allocate

    struct {
        volatile char event;
        int64_t last_used_bytes;
        struct fs_trunk_file_info *next;
    } util;  //for util manager queue
} FSTrunkFileInfo;

#endif
