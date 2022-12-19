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

typedef struct {
    int index;
    char path[PATH_MAX];
    char mark[64];
} DAStorePathEntry;

#ifdef __cplusplus
extern "C" {
#endif

    int da_store_path_index_init();

    void da_store_path_index_destroy();

    int da_store_path_index_count();

    int da_store_path_index_max();

    int store_path_check_mark(DAStorePathEntry *pentry, bool *regenerated);

    DAStorePathEntry *da_store_path_index_get(const char *path);

    int da_store_path_index_add(const char *path, int *index);

    int da_store_path_index_save();

#ifdef __cplusplus
}
#endif

#endif
