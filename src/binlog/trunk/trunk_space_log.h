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


#ifndef _TRUNK_SPACE_LOG_H
#define _TRUNK_SPACE_LOG_H

#include "../../storage_config.h"

#ifdef __cplusplus
extern "C" {
#endif

    int trunk_space_log_init();
    void trunk_space_log_destroy();

    int trunk_space_log_write(const int64_t version,
            const char op_type, DATrunkSpaceInfo *space);

#ifdef __cplusplus
}
#endif

#endif
