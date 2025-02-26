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


#ifndef _DA_TRUNK_MAKER_H
#define _DA_TRUNK_MAKER_H

#include "fastcommon/uniq_skiplist.h"
#include "fastcommon/multi_skiplist.h"
#include "../storage_config.h"
#include "trunk_allocator.h"

typedef void (*da_trunk_allocate_done_callback)(DATrunkAllocator *allocator,
        const int result, const bool is_new_trunk, void *arg);

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_maker_init(DAContext *ctx);

    int da_trunk_maker_start(DAContext *ctx);

    int da_trunk_maker_allocate_ex(DATrunkAllocator *allocator,
            const bool urgent, const bool need_lock,
            da_trunk_allocate_done_callback callback, void *arg);

#define da_trunk_maker_allocate(allocator) \
    da_trunk_maker_allocate_ex(allocator, false, true, NULL, NULL)

#ifdef __cplusplus
}
#endif

#endif
