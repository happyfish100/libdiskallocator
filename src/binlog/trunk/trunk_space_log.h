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

#define DA_SPACE_LOG_ADD_TO_CHAIN(space_chain, record) \
    do {  \
        record->next = NULL;  \
        if (space_chain->head == NULL) { \
            space_chain->head = record;  \
        } else { \
            FC_SET_CHAIN_TAIL_NEXT(*space_chain,    \
                    DATrunkSpaceLogRecord, record); \
        } \
        space_chain->tail = record; \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_space_log_init(DAContext *ctx);
    int da_trunk_space_log_start(DAContext *ctx);
    void da_trunk_space_log_destroy(DAContext *ctx);

    int da_trunk_space_log_calc_version(DAContext *ctx,
            const uint32_t trunk_id, int64_t *version);

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_record1(
            DASpaceLogReader *reader)
    {
        DATrunkSpaceLogRecord *record;

        if ((record=(DATrunkSpaceLogRecord *)fast_mblock_alloc_object(
                        &reader->record_allocator)) != NULL)
        {
            record->version = __sync_add_and_fetch(
                    &reader->current_version, 1);
        }

        return record;
    }

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_record(
            DAContext *ctx)
    {
        return da_trunk_space_log_alloc_record1(&ctx->space_log_ctx.reader);
    }

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_fill_record1(
            DAContext *ctx, const int64_t version, const int64_t oid,
            const int64_t fid, const char op_type, const DAPieceFieldStorage
            *storage, const int extra)
    {
        DATrunkSpaceLogRecord *record;
        if ((record=da_trunk_space_log_alloc_record(ctx)) == NULL) {
            return NULL;
        }

        record->oid = oid;
        record->fid = fid;
        record->extra = extra;
        record->op_type = op_type;
        record->storage.version = version;
        record->storage.trunk_id = storage->trunk_id;
        record->storage.length = storage->length;
        record->storage.offset = storage->offset;
        record->storage.size = storage->size;
        return record;
    }

    static inline DATrunkSpaceLogRecord *da_trunk_space_log_alloc_fill_record(
            DAContext *ctx, const int64_t version, const int64_t oid,
            const int64_t fid, const char op_type,
            const DAPieceFieldStorage *storage)
    {
        const int extra = 0;
        return da_trunk_space_log_alloc_fill_record1(ctx,
                version, oid, fid, op_type, storage, extra);
    }

    static inline void da_trunk_space_log_free_chain(
            DAContext *ctx, struct fc_queue_info *chain)
    {
        fc_queue_free_chain(&ctx->space_log_ctx.queue, &ctx->
                space_log_ctx.reader.record_allocator, chain);
    }

    static inline void da_trunk_space_log_push_chain(
            DAContext *ctx, struct fc_queue_info *qinfo)
    {
        fc_queue_push_queue_to_tail(&ctx->space_log_ctx.queue, qinfo);
    }

    int da_trunk_space_log_redo_by_chain(DAContext *ctx,
            struct fc_queue_info *chain);
    int da_trunk_space_log_redo_by_file(DAContext *ctx,
            const char *space_log_filename);

    int da_trunk_space_log_unlink(DAContext *ctx,
            const uint32_t trunk_id);

    static inline void da_trunk_space_log_pack(const DATrunkSpaceLogRecord
            *record, FastBuffer *buffer, const bool have_extra_field)
    {
        buffer->length += sprintf(buffer->data + buffer->length,
                "%u %"PRId64" %"PRId64" %"PRId64" %c %u %u %u %u",
                (uint32_t)g_current_time, record->storage.version,
                record->oid, record->fid, record->op_type,
                record->storage.trunk_id, record->storage.length,
                record->storage.offset, record->storage.size);
        if (have_extra_field) {
            buffer->length += sprintf(buffer->data + buffer->length,
                    " %u\n", record->extra);
        } else {
            *(buffer->data + buffer->length++) = '\n';
        }
    }

    int da_trunk_space_log_unpack(const string_t *line,
            DATrunkSpaceLogRecord *record, char *error_info,
            const bool have_extra_field);

    static inline void da_trunk_space_log_inc_waiting_count(
            DAContext *ctx, const int count)
    {
        sf_synchronize_counter_add(&ctx->space_log_ctx.notify, count);
    }

    static inline void da_trunk_space_log_wait(DAContext *ctx)
    {
        sf_synchronize_counter_wait(&ctx->space_log_ctx.notify);
    }

#ifdef __cplusplus
}
#endif

#endif
