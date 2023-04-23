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


#ifndef _DA_TRUNK_HASHTABLE_H
#define _DA_TRUNK_HASHTABLE_H

#include "../storage_config.h"

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_hashtable_init(DATrunkHTableContext *ctx);

    void da_trunk_hashtable_destroy(DATrunkHTableContext *ctx);

    int da_trunk_hashtable_count(DATrunkHTableContext *ctx);

    int da_trunk_hashtable_add(DATrunkHTableContext *ctx,
            DATrunkFileInfo *trunk);

    DATrunkFileInfo *da_trunk_hashtable_get_ex(DATrunkHTableContext *ctx,
            const uint64_t trunk_id, const int log_level);

#define da_trunk_hashtable_get(ctx, trunk_id) \
    da_trunk_hashtable_get_ex(ctx, trunk_id, LOG_ERR)

    void da_trunk_hashtable_iterator(DATrunkHTableContext *ctx,
            DATrunkHashtableIterator *it, const bool need_lock);

    DATrunkFileInfo *da_trunk_hashtable_next(DATrunkHashtableIterator *it);

    int da_trunk_hashtable_dump_to_file(DATrunkHTableContext *ctx,
            const char *filename, int64_t *total_trunk_count);

#ifdef __cplusplus
}
#endif

#endif
