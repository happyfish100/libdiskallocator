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


#ifndef _STORAGE_CONFIG_H
#define _STORAGE_CONFIG_H

#include "fastcommon/common_define.h"
#include "storage_types.h"

typedef struct {
    volatile int64_t total;
    volatile int64_t avail;  //current available space
    volatile int64_t used;
    int64_t last_used;      //for avail allocator check
} DATrunkSpaceStat;

typedef struct {
#ifdef OS_LINUX
    int block_size;
#endif
    DAStorePath store;
    int write_thread_count;
    int read_thread_count;
    int prealloc_trunks;
    int read_io_depth;
    struct {
        int64_t value;
        double ratio;
    } reserved_space;

    struct {
        int64_t value;
        double ratio;
        int trunk_count;  //calculate by: value / trunk_file_size
    } prealloc_space;

    struct {
        int64_t total;
        int64_t avail;  //current available space
        volatile time_t last_stat_time;
        double used_ratio;
    } space_stat;  //for disk space

    DATrunkSpaceStat trunk_stat;  //for trunk space
} DAStoragePathInfo;

typedef struct {
    DAStoragePathInfo *paths;
    int count;
} DAStoragePathArray;

typedef struct {
    DAStoragePathInfo **paths;
    int count;
} DAStoragePathPtrArray;

typedef struct {
    DAStoragePathArray store_path;
    DAStoragePathArray write_cache;
    DAStoragePathPtrArray paths_by_index;
    int max_store_path_index;  //the max of DAStorePath->index from dat file

    struct {
        double on_usage;  //usage ratio
        TimeInfo start_time;
        TimeInfo end_time;
    } write_cache_to_hd;

    int write_threads_per_path;
    int read_threads_per_path;
    int io_depth_per_read_thread;
    double reserved_space_per_disk;
    int max_trunk_files_per_subdir;
    uint32_t trunk_file_size;
    int discard_remain_space_size;
    int trunk_prealloc_threads;
    int fd_cache_capacity_per_read_thread;
    int fd_cache_capacity_per_write_thread;
    double reclaim_trunks_on_path_usage;
    double never_reclaim_on_trunk_usage;

    struct {
        double ratio_per_path;
        TimeInfo start_time;
        TimeInfo end_time;
    } prealloc_space;

#ifdef OS_LINUX
    struct {
        struct {
            int64_t value;
            double ratio;
        } memory_watermark_low;

        struct {
            int64_t value;
            double ratio;
        } memory_watermark_high;

        int max_idle_time;
        int reclaim_interval;
    } aio_read_buffer;
#endif

} DAStorageConfig;

#ifdef __cplusplus
extern "C" {
#endif

    int storage_config_load(DAStorageConfig *storage_cfg,
            const char *storage_filename);

    int storage_config_calc_path_avail_space(DAStoragePathInfo *path_info);

    void storage_config_stat_path_spaces(SFSpaceStat *ss);

    void storage_config_to_log(DAStorageConfig *storage_cfg);

    static inline int storage_config_path_count(DAStorageConfig *storage_cfg)
    {
        return storage_cfg->store_path.count + storage_cfg->write_cache.count;
    }

#ifdef __cplusplus
}
#endif

#endif
