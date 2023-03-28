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
#include "sf/sf_binlog_index.h"
#include "sf/sf_binlog_writer.h"
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
struct da_full_trunk_id_info;
struct da_trunk_file_info;
struct da_slice_entry;
struct da_trunk_space_info;

typedef void (*da_rw_done_callback_func)(
        struct da_slice_op_context *op_ctx, void *arg);

typedef int (*da_slice_migrate_done_callback)(
        const struct da_full_trunk_id_info *trunk,
        const struct da_piece_field_info *field,
        struct fc_queue_info *space_chain,
        SFSynchronizeContext *sctx, int *flags);

typedef void (*da_trunk_migrate_done_callback)(
        const struct da_trunk_file_info *trunk);

typedef int (*da_cached_slice_write_done_callback)(const
        struct da_slice_entry *se, const struct da_trunk_space_info
        *space, void *arg1, void *arg2);

typedef struct {
    int index;   //the inner index is important!
    string_t path;
} DAStorePath;

typedef struct da_trunk_id_info {
    int64_t id;
    uint32_t subdir;     //in which subdir
} DATrunkIdInfo;

typedef struct da_trunk_space_info {
    DAStorePath *store;
    DATrunkIdInfo id_info;
    uint32_t offset;  //offset of the trunk file
    uint32_t size;    //alloced space size
} DATrunkSpaceInfo;

typedef struct {
    DATrunkSpaceInfo space;
    int64_t version; //for write in order
} DATrunkSpaceWithVersion;

typedef struct da_full_trunk_id_info {
    DAStorePath *store;
    DATrunkIdInfo id_info;
} DAFullTrunkIdInfo;

typedef enum da_slice_type {
    DA_SLICE_TYPE_FILE  = 'F', /* in file slice */
    DA_SLICE_TYPE_CACHE = 'C', /* in memory cache */
    DA_SLICE_TYPE_ALLOC = 'A'  /* allocate slice (index and space allocate only) */
} DASliceType;

#ifdef OS_LINUX
typedef struct aio_buffer_ptr_array {
    int alloc;
    int count;
    struct da_aligned_read_buffer **buffers;
} AIOBufferPtrArray;

typedef enum {
    da_buffer_type_direct,
    da_buffer_type_aio
} DABufferType;
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
    uint64_t oid;  //object ID
    uint64_t fid;  //field ID (key)
    unsigned char source;
    DABinlogOpType op_type;
    int extra;     //such as slice offset
    DAPieceFieldStorage storage;
} DAPieceFieldInfo;

typedef struct da_piece_field_array {
    DAPieceFieldInfo *records;
    int count;
} DAPieceFieldArray;

typedef struct da_trunk_space_log_record {
    int64_t version; //for stable sort only
    uint64_t oid;    //object ID
    uint64_t fid;    //field ID (key)
    int extra;       //such as slice offset
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
    DABufferType type;
    DAAlignedReadBuffer *aio_buffer;   //NULL for alloc from pool
    BufferInfo buffer;
#else
    BufferInfo buffer;
#endif
    void *arg;  //for read done callback
} DATrunkReadBuffer;

typedef struct da_trunk_read_buffer_array {
    int alloc;
    int count;
    DATrunkReadBuffer *buffers;
} DATrunkReadBufferArray;

typedef struct da_slice_op_context {
    DAPieceFieldStorage *storage;
    DATrunkReadBuffer rb;
} DASliceOpContext;

typedef struct {
    volatile int64_t total;
    volatile int64_t avail;  //current available space
    volatile int64_t used;
    int64_t last_used;      //for avail allocator check
} DATrunkSpaceStat;

struct da_context;
typedef struct {
#ifdef OS_LINUX
    int block_size;
#endif
    DAStorePath store;
    int write_thread_count;
    int read_thread_count;
    int prealloc_trunks;
    int read_io_depth;
    bool read_direct_io;
    int fsync_every_n_writes;
    struct {
        int64_t value;
        double ratio;
    } reserved_space;

    struct {
        int64_t value;
        double ratio;
        int trunk_count;  //calculate by: value / trunk_file_size
    } prealloc_space;

    struct {
        int64_t total;
        int64_t avail;  //current available space
        volatile time_t last_stat_time;
        double used_ratio;
    } space_stat;  //for disk space

    DATrunkSpaceStat trunk_stat;  //for trunk space
    struct da_context *ctx;
} DAStoragePathInfo;

typedef struct {
    DAStoragePathInfo *paths;
    int count;
} DAStoragePathArray;

typedef struct {
    DAStoragePathInfo **paths;
    int count;
} DAStoragePathPtrArray;

typedef struct da_storage_config {
    DAStoragePathArray store_path;
    DAStoragePathArray write_cache;
    DAStoragePathPtrArray paths_by_index;
    int max_store_path_index;  //the max of DAStorePath->index from dat file

    struct {
        double on_usage;  //usage ratio
        TimeInfo start_time;
        TimeInfo end_time;
    } write_cache_to_hd;

    int write_threads_per_path;
    int read_threads_per_path;
    int io_depth_per_read_thread;
    bool read_direct_io;
    int fsync_every_n_writes;
    double reserved_space_per_disk;
    int max_trunk_files_per_subdir;
    uint32_t trunk_file_size;
    int discard_remain_space_size;
    int trunk_prealloc_threads;
    int fd_cache_capacity_per_read_thread;
    int fd_cache_capacity_per_write_thread;
    double reclaim_trunks_on_path_usage;
    double never_reclaim_on_trunk_usage;

    struct {
        double ratio_per_path;
        TimeInfo start_time;
        TimeInfo end_time;
    } prealloc_space;

#ifdef OS_LINUX
    struct {
        struct {
            int64_t value;
            double ratio;
        } memory_watermark_low;

        struct {
            int64_t value;
            double ratio;
        } memory_watermark_high;

        int max_idle_time;
        int reclaim_interval;
    } aio_read_buffer;
#endif

} DAStorageConfig;


typedef struct {
    string_t path;   //data path
    int binlog_buffer_size;
    int binlog_subdirs;
    int trunk_index_dump_interval;
    TimeInfo trunk_index_dump_base_time;
} DADataConfig;

typedef struct {
    DATrunkFileInfo **buckets;
    DATrunkFileInfo **end;
    int capacity;
    volatile int count;
} DATrunkHashtable;

typedef struct {
    int count;
    pthread_mutex_t *locks;
} DATrunkSharedLockArray;

typedef struct {
    DATrunkHashtable htable;
    DATrunkSharedLockArray lock_array;
} DATrunkHTableContext;

typedef struct {
    DATrunkHTableContext *ctx;
    DATrunkFileInfo **bucket;
    DATrunkFileInfo *current;
    bool need_lock;
} DATrunkHashtableIterator;

typedef struct {
    int index;
    char path[PATH_MAX];
    char mark[64];
} DAStorePathEntry;

typedef struct {
    int alloc;
    int count;
    DAStorePathEntry *entries;  //sort by index
} DAStorePathArray;

typedef struct da_trunk_space_log_record_array {
    DATrunkSpaceLogRecord **records;
    int count;
    int alloc;
} DATrunkSpaceLogRecordArray;

typedef struct da_space_log_reader {
    volatile int64_t current_version; //generate version for DATrunkSpaceLogRecord
    struct fast_mblock_man record_allocator;
    UniqSkiplistFactory factory;
    struct da_context *ctx;
} DASpaceLogReader;

/* trunk fd cache */
typedef struct da_trunk_id_fd_pair {
    uint32_t trunk_id;
    int fd;
} DATrunkIdFDPair;

typedef struct da_trunk_fd_cache_entry {
    DATrunkIdFDPair pair;
    struct fc_list_head dlink;
    struct da_trunk_fd_cache_entry *next;  //for hashtable
} DATrunkFDCacheEntry;

typedef struct {
    DATrunkFDCacheEntry **buckets;
    unsigned int size;
} DATrunkFDCacheHashtable;

typedef struct {
    DATrunkFDCacheHashtable htable;
    struct {
        int capacity;
        int count;
        struct fc_list_head head;
    } lru;
    struct fast_mblock_man allocator;
} DATrunkFDCacheContext;

typedef struct da_trunk_space_log_context {
    struct fc_queue queue;
    SFSynchronizeContext notify;
    DASpaceLogReader reader;
    DATrunkSpaceLogRecordArray record_array;
    DATrunkFDCacheContext fd_cache_ctx;
    FastBuffer buffer;
} DATrunkSpaceLogContext;

typedef struct da_context {
    const char *module_name;
    DADataConfig data;

    struct {
        int file_block_size;
        DAStorageConfig cfg;
        int read_direct_io_paths;
        bool have_extra_field;
        bool migrate_path_mark_filename; //for faststore
    } storage;

    bool check_trunk_avail_in_progress;
    DAStorePathArray store_path_array;
    SFBinlogIndexContext trunk_index_ctx;
    DATrunkHTableContext trunk_htable_ctx;
    SFBinlogWriterContext trunk_binlog_writer;
    DATrunkSpaceLogContext space_log_ctx;

    struct da_trunk_read_context  *trunk_read_ctx;
    struct da_trunk_write_context *trunk_write_ctx;
    struct da_read_buffer_pool_context *rbpool_ctx;

    struct da_trunk_id_info_context *trunk_id_info_ctx;
    struct da_storage_allocator_manager *store_allocator_mgr;
    struct da_trunk_prealloc_context *trunk_prealloc_ctx;
    struct da_trunk_maker_context *trunk_maker_ctx;

    da_slice_migrate_done_callback slice_migrate_done_callback;
    da_trunk_migrate_done_callback trunk_migrate_done_callback;
    da_cached_slice_write_done_callback cached_slice_write_done;
} DAContext;

#ifdef OS_LINUX
#define DA_OP_CTX_BUFFER_PTR(op_ctx) ((op_ctx).rb.type == da_buffer_type_aio ? \
        (op_ctx).rb.aio_buffer->buff + (op_ctx).rb.aio_buffer->offset : \
        (op_ctx).rb.buffer.buff)
#define DA_OP_CTX_BUFFER_LEN(op_ctx) ((op_ctx).rb.type == da_buffer_type_aio ? \
        (op_ctx).rb.aio_buffer->length : (op_ctx).rb.buffer.length)
#else
#define DA_OP_CTX_BUFFER_PTR(op_ctx) (op_ctx).rb.buffer.buff
#define DA_OP_CTX_BUFFER_LEN(op_ctx) (op_ctx).rb.buffer.length
#endif


#endif
