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

//binlog_reader.h

#ifndef _DA_BINLOG_READER_H_
#define _DA_BINLOG_READER_H_

#include "../common/write_fd_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

int da_binlog_reader_load_ex(const char *filename,
        da_binlog_unpack_record_func unpack_func, void *args);

int da_binlog_reader_load(const uint64_t id, void *args);

#ifdef __cplusplus
}
#endif

#endif
