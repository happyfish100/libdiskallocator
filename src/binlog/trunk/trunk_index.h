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

//trunk_index.h

#ifndef _DA_TRUNK_INDEX_H_
#define _DA_TRUNK_INDEX_H_

#include "sf/sf_binlog_index.h"
#include "../../storage_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern SFBinlogIndexContext g_da_trunk_index_ctx;

void da_trunk_index_init();

static inline int da_trunk_index_load()
{
    return sf_binlog_index_load(&g_da_trunk_index_ctx);
}

static inline int da_trunk_index_save()
{
    return sf_binlog_index_save(&g_da_trunk_index_ctx);
}

static inline int da_trunk_index_expand()
{
    return sf_binlog_index_expand(&g_da_trunk_index_ctx);
}

static inline void da_trunk_index_free()
{
    sf_binlog_index_free(&g_da_trunk_index_ctx);
}

#ifdef __cplusplus
}
#endif

#endif
