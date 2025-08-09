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


#ifndef _DA_TRUNK_BINLOG_H
#define _DA_TRUNK_BINLOG_H

#include "../../storage_config.h"

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_binlog_init(DAContext *ctx);
    void da_trunk_binlog_destroy(DAContext *ctx);

    static inline const char *da_trunk_binlog_get_filepath(
            DAContext *ctx, char *filepath, const int size)
    {
        return sf_binlog_writer_get_filepath(ctx->data.path.str,
                DA_TRUNK_BINLOG_SUBDIR_NAME, filepath, size);
    }

    static inline const char *da_trunk_binlog_get_filename(DAContext *ctx,
            const int binlog_index, char *filename, const int size)
    {
        return sf_binlog_writer_get_filename(ctx->data.path.str,
                DA_TRUNK_BINLOG_SUBDIR_NAME, binlog_index,
                filename, size);
    }

    static inline int da_trunk_binlog_get_current_write_index(DAContext *ctx)
    {
        return sf_binlog_get_current_write_index(
                &ctx->trunk_binlog_writer.writer);
    }

    static inline int da_trunk_binlog_set_binlog_write_index(
            DAContext *ctx, const int binlog_index)
    {
        /* force write to binlog index file */
        ctx->trunk_binlog_writer.writer.fw.binlog.last_index = -1;
        return sf_binlog_writer_set_binlog_write_index(&ctx->
                trunk_binlog_writer.writer, binlog_index);
    }

    static inline int da_trunk_binlog_log_to_buff(const char op_type,
            const int path_index, const DATrunkIdInfo *id_info,
            const uint32_t file_size, char *buff)
    {
        char *p;

        p = buff;
        p += fc_itoa(g_current_time, p);
        *p++ = ' ';
        *p++ = op_type;
        *p++ = ' ';
        p += fc_itoa(path_index, p);
        *p++ = ' ';
        p += fc_itoa(id_info->id, p);
        *p++ = ' ';
        p += fc_itoa(id_info->subdir, p);
        *p++ = ' ';
        p += fc_itoa(file_size, p);
        *p++ = '\n';
        *p = '\0';
        return p - buff;
    }

    int da_trunk_binlog_write(DAContext *ctx, const char op_type,
            const int path_index, const DATrunkIdInfo *id_info,
            const uint32_t file_size);

    int da_trunk_binlog_get_last_id_info(DAContext *ctx,
            DATrunkIdInfo *id_info);

#ifdef __cplusplus
}
#endif

#endif
