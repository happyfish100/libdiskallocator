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

typedef struct {
    DATrunkFileInfo **bucket;
    DATrunkFileInfo *current;
    bool need_lock;
} DATrunkHashtableIterator;

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_hashtable_init();

    void da_trunk_hashtable_destroy();

    int da_trunk_hashtable_count();

    int da_trunk_hashtable_add(DATrunkFileInfo *trunk);

    DATrunkFileInfo *da_trunk_hashtable_get(const uint32_t trunk_id);

    void da_trunk_hashtable_iterator(DATrunkHashtableIterator *it,
            const bool need_lock);

    DATrunkFileInfo *da_trunk_hashtable_next(DATrunkHashtableIterator *it);

#ifdef __cplusplus
}
#endif

#endif
