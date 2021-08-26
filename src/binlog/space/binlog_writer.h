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

//binlog_writer.h

#ifndef _DA_BINLOG_WRITER_H_
#define _DA_BINLOG_WRITER_H_

#include "../common/binlog_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int da_binlog_writer_init();

int da_binlog_writer_log(DABinlogWriter *writer, void *args);

int da_binlog_writer_synchronize(DABinlogWriter *writer);

int da_binlog_writer_shrink(DABinlogWriter *writer);

void da_binlog_writer_finish();

#ifdef __cplusplus
}
#endif

#endif
