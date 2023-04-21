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


#ifndef _SPACE_LOG_READER_H
#define _SPACE_LOG_READER_H

#include "fastcommon/uniq_skiplist.h"
#include "../../storage_types.h"

#ifdef __cplusplus
extern "C" {
#endif

    int da_space_log_reader_init(DASpaceLogReader *reader, DAContext *ctx,
            const int alloc_skiplist_once, const bool use_lock);

    void da_space_log_reader_destroy(DASpaceLogReader *reader);

    int da_space_log_reader_load(DASpaceLogReader *reader,
            const uint32_t trunk_id, UniqSkiplist **skiplist);

    int da_space_log_reader_load_to_chain(DASpaceLogReader *reader,
            const char *space_log_filename, struct fc_queue_info *chain);

#ifdef __cplusplus
}
#endif

#endif
