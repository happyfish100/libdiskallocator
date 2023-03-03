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


#ifndef _DA_TRUNK_FREELIST_H
#define _DA_TRUNK_FREELIST_H

#include "../storage_types.h"

struct da_trunk_allocator;
typedef struct {
    int count;
    int water_mark_trunks;
    DATrunkFileInfo *head;  //allocate from head
    DATrunkFileInfo *tail;  //push to tail
    pthread_lock_cond_pair_t lcp;  //for lock and notify
} DATrunkFreelist;

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_freelist_init(DATrunkFreelist *freelist);

    void da_trunk_freelist_keep_water_mark(struct da_trunk_allocator
            *allocator);

    void da_trunk_freelist_add(DATrunkFreelist *freelist,
            DATrunkFileInfo *trunk_info);

    int da_trunk_freelist_alloc_space(struct da_trunk_allocator *allocator,
            DATrunkFreelist *freelist, const uint64_t blk_hc, const int size,
            DATrunkSpaceWithVersion *spaces, int *count, const bool is_normal);

#ifdef __cplusplus
}
#endif

#endif
