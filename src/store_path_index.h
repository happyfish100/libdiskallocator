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


#ifndef _DA_STORE_PATH_INDEX_H
#define _DA_STORE_PATH_INDEX_H

#include <limits.h>
#include "storage_config.h"

#ifdef __cplusplus
extern "C" {
#endif

    int da_store_path_index_init(DAContext *ctx);

    void da_store_path_index_destroy(DAContext *ctx);

    int da_store_path_index_count(DAContext *ctx);

    int da_store_path_index_max(DAContext *ctx);

    int store_path_check_mark(DAContext *ctx, DAStorePathEntry *pentry,
            bool *regenerated);

    DAStorePathEntry *da_store_path_index_get(
            DAContext *ctx, const char *path);

    DAStorePathEntry *da_store_path_index_fetch(
            DAContext *ctx, const int index);

    int da_store_path_index_add(DAContext *ctx,
            const char *path, int *index);

    int da_store_path_index_save(DAContext *ctx);

    const char *da_store_path_index_get_filename(DAContext *ctx,
            char *full_filename, const int size);

#ifdef __cplusplus
}
#endif

#endif
