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

#ifndef _BINLOG_READER_H_
#define _BINLOG_READER_H_

typedef int (*binlog_parse_record_func)(const string_t *line,
        void *args, char *error_info);

#ifdef __cplusplus
extern "C" {
#endif

int binlog_reader_load(const char *subdir_name, const int64_t binlog_id,
        binlog_parse_record_func parse_record, void *args);

#ifdef __cplusplus
}
#endif

#endif
