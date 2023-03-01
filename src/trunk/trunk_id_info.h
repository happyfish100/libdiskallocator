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


#ifndef _DA_TRUNK_ID_INFO_H
#define _DA_TRUNK_ID_INFO_H

#include "../storage_config.h"

#ifdef __cplusplus
extern "C" {
#endif

    int da_trunk_id_info_init(DAContext *ctx);

    void da_trunk_id_info_destroy(DAContext *ctx);

    int da_trunk_id_info_add(DAContext *ctx, const int path_index,
        const DATrunkIdInfo *id_info);

    int da_trunk_id_info_delete(DAContext *ctx, const int path_index,
        const DATrunkIdInfo *id_info);

    int da_trunk_id_info_generate(DAContext *ctx,
        const int path_index, DATrunkIdInfo *id_info);

#ifdef __cplusplus
}
#endif

#endif
