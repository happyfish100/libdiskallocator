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

#include "fastcommon/fc_atomic.h"
#include "sf/sf_func.h"
#include "../../storage_config.h"
#include "../../dio/trunk_fd_cache.h"
#include "space_log_reader.h"

typedef struct da_trunk_space_log_record_array {
    DATrunkSpaceLogRecord **records;
    int count;
    int alloc;
} DATrunkSpaceLogRecordArray;

typedef struct da_trunk_space_log_context {
    struct fc_queue queue;
    SFSynchronizeContext notify;
    DASpaceLogReader reader;
    DATrunkSpaceLogRecordArray record_array;
    TrunkFDCacheContext fd_cache_ctx;
    FastBuffer buffer;
    time_t next_dump_time;
} DATrunkSpaceLogContext;

#define DA_SPACE_LOG_RECORD_ALLOCATOR g_trunk_space_log_ctx.reader.record_allocator
#define DA_SPACE_LOG_SKIPLIST_FACTORY g_trunk_space_log_ctx.reader.factory

#ifdef __cplusplus
extern "C" {
#endif

    extern DATrunkSpaceLogContext g_trunk_space_log_ctx;

    int da_trunk_space_log_init();
    void da_trunk_space_log_destroy();

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_record()
    {
        return (DATrunkSpaceLogRecord *)fast_mblock_alloc_object(
                &DA_SPACE_LOG_RECORD_ALLOCATOR);
    }

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_fill_record(
            const int64_t version, const int64_t oid, const unsigned char fid,
            const char op_type, const DAPieceFieldStorage *storage)
    {
        DATrunkSpaceLogRecord *record;
        if ((record=da_trunk_space_log_alloc_record()) == NULL) {
            return NULL;
        }

        record->oid = oid;
        record->fid = fid;
        record->op_type = op_type;
        record->storage.version = version;
        record->storage.trunk_id = storage->trunk_id;
        record->storage.length = storage->length;
        record->storage.offset = storage->offset;
        record->storage.size = storage->size;
        return record;
    }

    static inline int da_trunk_space_log_alloc_chain(const int count,
            struct fc_queue_info *chain)
    {
        return fc_queue_alloc_chain(&g_trunk_space_log_ctx.queue,
                &DA_SPACE_LOG_RECORD_ALLOCATOR, count, chain);
    }

    static inline void da_trunk_space_log_free_chain(
            struct fc_queue_info *chain)
    {
        fc_queue_free_chain(&g_trunk_space_log_ctx.queue,
                &DA_SPACE_LOG_RECORD_ALLOCATOR, chain);
    }

    static inline void da_trunk_space_log_push_chain(
            struct fc_queue_info *qinfo)
    {
        fc_queue_push_queue_to_tail(&g_trunk_space_log_ctx.queue, qinfo);
    }

    int da_trunk_space_log_redo(struct fc_queue_info *qinfo);

    static inline void da_trunk_space_log_pack(const DATrunkSpaceLogRecord
            *record, FastBuffer *buffer)
    {
        buffer->length += sprintf(buffer->data + buffer->length,
                "%u %"PRId64" %"PRId64" %c %u %u %u %u %u\n",
                (uint32_t)g_current_time, record->storage.version,
                record->oid, record->op_type, record->fid,
                record->storage.trunk_id, record->storage.length,
                record->storage.offset, record->storage.size);
    }

    int da_trunk_space_log_unpack(const string_t *line,
            DATrunkSpaceLogRecord *record, char *error_info);

    static inline void da_trunk_space_log_inc_waiting_count(const int count)
    {
        FC_ATOMIC_INC_EX(g_trunk_space_log_ctx.notify.waiting_count, count);
    }

    static inline void da_trunk_space_log_wait()
    {
        sf_synchronize_counter_wait(&g_trunk_space_log_ctx.notify);
    }

#ifdef __cplusplus
}
#endif

#endif
