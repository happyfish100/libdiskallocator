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

#include "../../storage_config.h"
#include "../../dio/trunk_fd_cache.h"

typedef struct da_trunk_space_log_record_array {
    DATrunkSpaceLogRecord **records;
    int count;
    int alloc;
} DATrunkSpaceLogRecordArray;

typedef struct da_trunk_space_log_context {
    struct fc_queue queue;
    SFSynchronizeContext notify;
    struct fast_mblock_man record_allocator;
    DATrunkSpaceLogRecordArray record_array;
    TrunkFDCacheContext fd_cache_ctx;
    FastBuffer buffer;
    time_t next_dump_time;
} DATrunkSpaceLogContext;

#ifdef __cplusplus
extern "C" {
#endif

    extern DATrunkSpaceLogContext g_trunk_space_log_ctx;

    int da_trunk_space_log_init();
    void da_trunk_space_log_destroy();

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_record()
    {
        return (DATrunkSpaceLogRecord *)fast_mblock_alloc_object(
                &g_trunk_space_log_ctx.record_allocator);
    }

#define DA_TRUNK_SPACE_LOG_SET_RECORD_EX(record, _version, \
        _oid, _fid, _op_type, _trunk_id, _offset, _size)   \
        (record)->oid = _oid;         \
        (record)->fid = _fid;         \
        (record)->op_type = _op_type; \
        (record)->storage.version = _version;   \
        (record)->storage.trunk_id = _trunk_id; \
        (record)->storage.offset = _offset;     \
        (record)->storage.size = _size

#define DA_TRUNK_SPACE_LOG_SET_RECORD(record, _version, \
        _oid, _fid, _op_type, _storage)  \
    DA_TRUNK_SPACE_LOG_SET_RECORD_EX(record, _version, \
        _oid, _fid, _op_type, (_storage).trunk_id,  \
        (_storage).offset, (_storage).size)

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_fill_record_ex(
            const int64_t version, const int64_t oid, const unsigned char fid,
            const char op_type, const uint32_t trunk_id, const uint32_t offset,
            const uint32_t size)
    {
        DATrunkSpaceLogRecord *record;
        if ((record=da_trunk_space_log_alloc_record()) == NULL) {
            return NULL;
        }

        DA_TRUNK_SPACE_LOG_SET_RECORD_EX(record, version,
                oid, fid, op_type, trunk_id, offset, size);
        return record;
    }

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_fill_record(
            const int64_t version, const int64_t oid, const unsigned char fid,
            const char op_type, const DAPieceFieldStorage *storage)
    {
        DATrunkSpaceLogRecord *record;
        if ((record=da_trunk_space_log_alloc_record()) == NULL) {
            return NULL;
        }

        DA_TRUNK_SPACE_LOG_SET_RECORD(record, version,
                oid, fid, op_type, *storage);
        return record;
    }

    static inline int da_trunk_space_log_alloc_chain(const int count,
            struct fc_queue_info *chain)
    {
        return fc_queue_alloc_chain(&g_trunk_space_log_ctx.queue,
                &g_trunk_space_log_ctx.record_allocator, count, chain);
    }

    static inline void da_trunk_space_log_push_chain(
            struct fc_queue_info *qinfo)
    {
        fc_queue_push_queue_to_tail(&g_trunk_space_log_ctx.queue, qinfo);
    }

    static inline void da_trunk_space_log_pack(const DATrunkSpaceLogRecord
            *record, FastBuffer *buffer)
    {
        buffer->length += sprintf(buffer->data + buffer->length,
                "%u %"PRId64" %"PRId64" %c %u %u %u %u\n",
                (uint32_t)g_current_time, record->storage.version,
                record->oid, record->op_type, record->fid,
                record->storage.trunk_id, record->storage.offset,
                record->storage.size);
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
