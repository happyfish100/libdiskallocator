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


#ifndef _DA_STORAGE_CONFIG_H
#define _DA_STORAGE_CONFIG_H

#include "fastcommon/common_define.h"
#include "storage_types.h"

#ifdef __cplusplus
extern "C" {
#endif

    int da_storage_config_load(DAContext *ctx, DAStorageConfig *storage_cfg,
            const char *storage_filename);

    int da_storage_config_calc_path_avail_space(DAStoragePathInfo *path_info);

    void da_storage_config_stat_path_spaces(DAContext *ctx, SFSpaceStat *ss);

    void da_storage_config_to_log(DAContext *ctx, DAStorageConfig *storage_cfg);

    static inline int da_storage_config_path_count(DAStorageConfig *storage_cfg)
    {
        return storage_cfg->store_path.count + storage_cfg->write_cache.count;
    }

#ifdef __cplusplus
}
#endif

#endif
