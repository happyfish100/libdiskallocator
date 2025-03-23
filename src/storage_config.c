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

#include <limits.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include "fastcommon/ini_file_reader.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/system_info.h"
#include "sf/sf_global.h"
#include "global.h"
#include "store_path_index.h"
#include "storage_config.h"

static int load_one_path(DAContext *ctx, DAStorageConfig *storage_cfg,
        IniFullContext *ini_ctx, string_t *path)
{
    int result;
    char tmp_filename[PATH_MAX];
    char full_path[PATH_MAX];
    char *path_str;

    path_str = iniGetStrValue(ini_ctx->section_name,
            "path", ini_ctx->context);
    if (path_str == NULL) {
        path_str = ctx->data.path.str;
    } else if (*path_str == '\0') {
        logError("file: "__FILE__", line: %d, %s "
                "config file: %s, section: %s, item: path is empty",
                __LINE__, ctx->module_name, ini_ctx->filename,
                ini_ctx->section_name);
        return ENOENT;
    } else {
        if (*path_str != '/') {
            snprintf(tmp_filename, sizeof(tmp_filename),
                    "%s/dummy.tmp", ctx->data.path.str);
            resolve_path(tmp_filename, path_str,
                    full_path, sizeof(full_path));
            path_str = full_path;
        }
    }

    if (access(path_str, F_OK) == 0) {
        if (!isDir(path_str)) {
            logError("file: "__FILE__", line: %d, %s "
                    "config file: %s, section: %s, item: path, "
                    "%s is NOT a path", __LINE__, ctx->module_name,
                    ini_ctx->filename, ini_ctx->section_name, path_str);
            return EINVAL;
        }
    } else {
        result = errno != 0 ? errno : EPERM;
        if (result != ENOENT) {
            logError("file: "__FILE__", line: %d, %s "
                    "config file: %s, section: %s, access path %s fail, "
                    "errno: %d, error info: %s", __LINE__, ctx->module_name,
                    ini_ctx->filename, ini_ctx->section_name, path_str,
                    result, STRERROR(result));
            return result;
        }

        if (mkdir(path_str, 0775) != 0) {
            result = errno != 0 ? errno : EPERM;
            logError("file: "__FILE__", line: %d, %s "
                    "mkdir %s fail, errno: %d, error info: %s", __LINE__,
                    ctx->module_name, path_str, result, STRERROR(result));
            return result;
        }
        
        SF_CHOWN_RETURN_ON_ERROR(path_str, geteuid(), getegid());
    }

    chopPath(path_str);
    path->len = strlen(path_str);
    path->str = (char *)fc_malloc(path->len + 1);
    if (path->str == NULL) {
        return ENOMEM;
    }

    memcpy(path->str, path_str, path->len + 1);
    return 0;
}

static int da_storage_config_calc_path_spaces(DAStoragePathInfo *path_info)
{
    struct statvfs sbuf;

    if (statvfs(path_info->store.path.str, &sbuf) != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "statvfs path %s fail, errno: %d, error info: %s",
                __LINE__, path_info->ctx->module_name, path_info->
                store.path.str, errno, STRERROR(errno));
        return errno != 0 ? errno : EPERM;
    }

    path_info->space_stat.total = (int64_t)(sbuf.f_blocks) * sbuf.f_frsize;
    path_info->space_stat.avail = (int64_t)(sbuf.f_bavail) * sbuf.f_frsize;
    path_info->reserved_space.value = path_info->space_stat.total *
        path_info->reserved_space.ratio;
    if (sbuf.f_blocks > 0) {
        path_info->space_stat.used_ratio = (double)(sbuf.f_blocks -
                sbuf.f_bavail) / (double)sbuf.f_blocks;
    }

    if (path_info->ctx->storage.cfg.prealloc_trunks.enabled) {
        path_info->prealloc_trunks.value = path_info->space_stat.total *
            path_info->prealloc_trunks.ratio;
        path_info->prealloc_trunks.count = (path_info->prealloc_trunks.
                value + path_info->ctx->storage.cfg.trunk_file_size - 1) /
            (int64_t)path_info->ctx->storage.cfg.trunk_file_size;
    }

    /*
    logInfo("%s used ratio: %.2f%%, prealloc_trunks.count: %d",
            path_info->ctx->module_name, 100 * path_info->space_stat.
            used_ratio, path_info->prealloc_trunks.count);
            */

    __sync_bool_compare_and_swap(&path_info->space_stat.
            last_stat_time, 0, g_current_time);
    return 0;
}

int da_storage_config_calc_path_avail_space(DAStoragePathInfo *path_info)
{
    struct statvfs sbuf;
    time_t last_stat_time;

    last_stat_time = __sync_add_and_fetch(&path_info->
            space_stat.last_stat_time, 0);
    if (last_stat_time == g_current_time) {
        return 0;
    }
    __sync_bool_compare_and_swap(&path_info->space_stat.
            last_stat_time, last_stat_time, g_current_time);

    if (statvfs(path_info->store.path.str, &sbuf) != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "statvfs path %s fail, errno: %d, error info: %s",
                __LINE__, path_info->ctx->module_name, path_info->
                store.path.str, errno, STRERROR(errno));
        return errno != 0 ? errno : EPERM;
    }

    path_info->space_stat.total = (int64_t)(sbuf.f_blocks) * sbuf.f_frsize;
    path_info->space_stat.used = (sbuf.f_blocks -
            sbuf.f_bavail) * sbuf.f_frsize;
    path_info->space_stat.avail = (int64_t)(sbuf.f_bavail) * sbuf.f_frsize;
    if (sbuf.f_blocks > 0) {
        path_info->space_stat.used_ratio = (double)(sbuf.f_blocks -
                sbuf.f_bavail) / (double)sbuf.f_blocks;
    }

    return 0;
}

void da_storage_config_stat_path_spaces_ex(DAContext *ctx, DASpaceStat *ss)
{
    DAStoragePathInfo **pp;
    DAStoragePathInfo **end;
    int64_t disk_avail;

    ss->disk.total = ss->disk.used = ss->disk.avail = 0;
    ss->trunk.total = ss->trunk.used = ss->trunk.avail = 0;
    end = ctx->storage.cfg.paths_by_index.paths +
        ctx->storage.cfg.paths_by_index.count;
    for (pp=ctx->storage.cfg.paths_by_index.paths; pp<end; pp++) {
        if (*pp == NULL) {
            continue;
        }

        da_storage_config_calc_path_avail_space(*pp);
        disk_avail = (*pp)->space_stat.avail - (*pp)->reserved_space.value;
        if (disk_avail < 0) {
            disk_avail = 0;
        }

        ss->disk.total += (*pp)->space_stat.total;
        ss->disk.used += (*pp)->space_stat.used;
        ss->disk.avail += disk_avail;
        ss->trunk.total += (*pp)->trunk_stat.total;
        ss->trunk.used += (*pp)->trunk_stat.used;
        ss->trunk.avail += (*pp)->trunk_stat.avail;

        /*
        logInfo("%s trunk {total: %"PRId64" MB, avail: %"PRId64" MB, "
                "used: %"PRId64" MB, reserved: %"PRId64" MB}, "
                "disk_avail: %"PRId64" MB, sum {total: %"PRId64" MB, "
                "avail: %"PRId64" MB, used: %"PRId64" MB}",
                ctx->module_name, (*pp)->trunk_stat.total / (1024 * 1024),
                (*pp)->trunk_stat.avail / (1024 * 1024),
                (*pp)->trunk_stat.used / (1024 * 1024),
                (*pp)->reserved_space.value / (1024 * 1024),
                disk_avail / (1024 * 1024), ss->trunk.total / (1024 * 1024),
                ss->trunk.avail / (1024 * 1024), ss->trunk.used / (1024 * 1024));
                */
    }
}

static int load_write_align_size_from_config(DAContext *ctx,
        IniFullContext *ini_ctx, const int default_value,
        int *write_align_size)
{
    *write_align_size = iniGetIntValue(ini_ctx->section_name,
            "write_align_size", ini_ctx->context, default_value);
    if (*write_align_size < 0) {
        logError("file: "__FILE__", line: %d, %s "
                "config file: %s, invalid write_align_size: %d < 0!",
                __LINE__, ctx->module_name, ini_ctx->filename,
                *write_align_size);
        return EINVAL;
    } else if (*write_align_size > 0) {
        if (!is_power2(*write_align_size)) {
            logError("file: "__FILE__", line: %d, %s "
                    "config file: %s, invalid write_align_size: %d "
                    "which is NOT power 2!", __LINE__, ctx->module_name,
                    ini_ctx->filename, *write_align_size);
            return EINVAL;
        }
    }

    return 0;
}

static int load_paths(DAContext *ctx, DAStorageConfig *storage_cfg,
        IniFullContext *ini_ctx, const char *section_name_prefix,
        const char *item_name, DAStoragePathArray *parray,
        const bool required)
{
    int result;
    int section_count;
    int item_count;
    int bytes;
    int i, k;
    const char *old_section_name;
    char section_name[64];

    section_count = iniGetIntValue(NULL, item_name, ini_ctx->context, 0);
    if (section_count <= 0) {
        if (required) {
            logError("file: "__FILE__", line: %d, %s "
                    "config file: %s, item \"%s\" not exist "
                    "or invalid", __LINE__, ctx->module_name,
                    ini_ctx->filename, item_name);
            return ENOENT;
        } else {
            parray->count = 0;
            return 0;
        }
    }

    bytes = sizeof(DAStoragePathInfo) * section_count;
    parray->paths = (DAStoragePathInfo *)fc_malloc(bytes);
    if (parray->paths == NULL) {
        return ENOMEM;
    }
    memset(parray->paths, 0, bytes);

    old_section_name = ini_ctx->section_name;
    ini_ctx->section_name = section_name;
    for (i=0; i<section_count; i++) {
        sprintf(section_name, "%s-%d", section_name_prefix, i + 1);
        if (i > 0 && iniGetSectionItems(section_name,
                    ini_ctx->context, &item_count) == NULL)
        {
            logError("file: "__FILE__", line: %d, %s "
                    "config file: %s, section [%s] not exist", __LINE__,
                    ctx->module_name, ini_ctx->filename, section_name);
            return ENOENT;
        }

        parray->paths[i].ctx = ctx;
        if ((result=load_one_path(ctx, storage_cfg, ini_ctx,
                        &parray->paths[i].store.path)) != 0)
        {
            return result;
        }

        parray->paths[i].write_thread_count = iniGetIntValue(section_name,
                "write_threads", ini_ctx->context, storage_cfg->
                write_threads_per_path);
        if (parray->paths[i].write_thread_count <= 0) {
            parray->paths[i].write_thread_count = 1;
        }

        parray->paths[i].read_thread_count = iniGetIntValue(section_name,
                "read_threads", ini_ctx->context, storage_cfg->
                read_threads_per_path);
        if (parray->paths[i].read_thread_count <= 0) {
            parray->paths[i].read_thread_count = 1;
        }

        parray->paths[i].read_io_depth = iniGetIntValue(section_name,
                "read_io_depth", ini_ctx->context, storage_cfg->
                io_depth_per_read_thread);
        if (parray->paths[i].read_io_depth <= 0) {
            parray->paths[i].read_io_depth = 64;
        }

#ifdef OS_LINUX
        parray->paths[i].write_direct_io = iniGetBoolValue(
                section_name, "write_direct_io", ini_ctx->context,
                storage_cfg->write_direct_io);
        parray->paths[i].read_direct_io = iniGetBoolValue(
                section_name, "read_direct_io", ini_ctx->context,
                storage_cfg->read_direct_io);
        if (parray->paths[i].read_direct_io) {
            ++ctx->storage.read_direct_io_paths;
        }
#else
        parray->paths[i].write_direct_io = false;
        parray->paths[i].read_direct_io = false;
#endif

        if ((result=load_write_align_size_from_config(ctx, ini_ctx,
                        storage_cfg->write_align_size, &parray->
                        paths[i].write_align_size)) != 0)
        {
            return result;
        }

        parray->paths[i].fsync_every_n_writes = iniGetIntValue(
                section_name, "fsync_every_n_writes", ini_ctx->context,
                storage_cfg->fsync_every_n_writes);

        if ((result=iniGetPercentValue(ini_ctx, "prealloc_trunks",
                        &parray->paths[i].prealloc_trunks.ratio,
                        storage_cfg->prealloc_trunks.ratio_per_path)) != 0)
        {
            return result;
        }

        if ((result=iniGetPercentValue(ini_ctx, "reserved_space",
                        &parray->paths[i].reserved_space.ratio,
                        storage_cfg->reserved_space_per_disk)) != 0)
        {
            return result;
        }

        if ((result=da_storage_config_calc_path_spaces(
                        parray->paths + i)) != 0)
        {
            return result;
        }
    }

    for (i=0; i<section_count; i++) {
        for (k=i+1; k<section_count; k++) {
            if (fc_string_equal(&parray->paths[i].store.path,
                        &parray->paths[k].store.path))
            {
                logError("file: "__FILE__", line: %d, %s "
                        "config file: %s, store path #%d equals "
                        "store path #%d, store path: %s", __LINE__,
                        ctx->module_name, ini_ctx->filename, i + 1,
                        k + 1, parray->paths[i].store.path.str);
                return EEXIST;
            }
        }
    }

    ini_ctx->section_name = old_section_name;
    parray->count = section_count;
    return 0;
}

#ifdef OS_LINUX
static int load_aio_read_buffer_params(DAStorageConfig *storage_cfg,
        IniFullContext *ini_ctx)
{
    int result;
    int64_t total_memory;

    ini_ctx->section_name = "aio-read-buffer";
    if ((result=iniGetPercentValue(ini_ctx, "memory_watermark_low",
                    &storage_cfg->aio_read_buffer.memory_watermark_low.
                    ratio, 0.01)) != 0)
    {
        return result;
    }

    if ((result=iniGetPercentValue(ini_ctx, "memory_watermark_high",
                    &storage_cfg->aio_read_buffer.memory_watermark_high.
                    ratio, 0.10)) != 0)
    {
        return result;
    }

    if ((result=get_sys_total_mem_size(&total_memory)) != 0) {
        return result;
    }

    storage_cfg->aio_read_buffer.memory_watermark_low.value =
        (int64_t)(total_memory * storage_cfg->aio_read_buffer.
                memory_watermark_low.ratio);
    storage_cfg->aio_read_buffer.memory_watermark_high.value =
        (int64_t)(total_memory * storage_cfg->aio_read_buffer.
                memory_watermark_high.ratio);

    storage_cfg->aio_read_buffer.max_idle_time = iniGetIntValue(
            ini_ctx->section_name, "max_idle_time",
            ini_ctx->context, 300);
    if (storage_cfg->aio_read_buffer.max_idle_time <= 0) {
        storage_cfg->aio_read_buffer.max_idle_time = 300;
    }

    storage_cfg->aio_read_buffer.reclaim_interval = iniGetIntValue(
            ini_ctx->section_name, "reclaim_interval",
            ini_ctx->context, 60);
    if (storage_cfg->aio_read_buffer.reclaim_interval <= 0) {
        storage_cfg->aio_read_buffer.reclaim_interval = 60;
    }

    return 0;
}
#endif

static int load_prealloc_trunks_items(DAContext *ctx,
        DAStorageConfig *storage_cfg,
        IniFullContext *ini_ctx)
{
    int result;
    const char *old_section_name;

    old_section_name = ini_ctx->section_name;
    ini_ctx->section_name = "prealloc-trunks";
    storage_cfg->prealloc_trunks.enabled = iniGetBoolValue(ini_ctx->
            section_name, "enabled", ini_ctx->context, false);
    if ((result=iniGetPercentValue(ini_ctx, "ratio_per_path",
                    &storage_cfg->prealloc_trunks.ratio_per_path, 0.05)) != 0)
    {
        return result;
    }

    if ((result=get_time_item_from_conf(ini_ctx->context,
                    "start_time", &storage_cfg->
                    prealloc_trunks.start_time, 1, 30)) != 0)
    {
        return result;
    }
    if ((result=get_time_item_from_conf(ini_ctx->context,
                    "end_time", &storage_cfg->
                    prealloc_trunks.end_time, 3, 30)) != 0)
    {
        return result;
    }

    storage_cfg->prealloc_trunks.threads = iniGetIntValue(ini_ctx->
            section_name, "threads", ini_ctx->context, 1);
    if (storage_cfg->prealloc_trunks.threads <= 0) {
        storage_cfg->prealloc_trunks.threads = 1;
    }

    ini_ctx->section_name = old_section_name;
    return 0;
}

static int load_global_items(DAContext *ctx,
        DAStorageConfig *storage_cfg,
        IniFullContext *ini_ctx)
{
    int result;

    storage_cfg->fd_cache_capacity_per_read_thread = iniGetIntValue(NULL,
            "fd_cache_capacity_per_read_thread", ini_ctx->context, 256);
    if (storage_cfg->fd_cache_capacity_per_read_thread <= 0) {
        storage_cfg->fd_cache_capacity_per_read_thread = 256;
    }

    storage_cfg->fd_cache_capacity_per_write_thread = iniGetIntValue(NULL,
            "fd_cache_capacity_per_write_thread", ini_ctx->context, 256);
    if (storage_cfg->fd_cache_capacity_per_write_thread <= 0) {
        storage_cfg->fd_cache_capacity_per_write_thread = 256;
    }

    storage_cfg->write_threads_per_path = iniGetIntValue(NULL,
            "write_threads_per_path", ini_ctx->context, 1);
    if (storage_cfg->write_threads_per_path <= 0) {
        storage_cfg->write_threads_per_path = 1;
    }

    storage_cfg->read_threads_per_path = iniGetIntValue(NULL,
            "read_threads_per_path", ini_ctx->context, 1);
    if (storage_cfg->read_threads_per_path <= 0) {
        storage_cfg->read_threads_per_path = 1;
    }

    storage_cfg->io_depth_per_read_thread = iniGetIntValue(NULL,
            "io_depth_per_read_thread", ini_ctx->context, 64);
    if (storage_cfg->io_depth_per_read_thread <= 0) {
        storage_cfg->io_depth_per_read_thread = 64;
    }

#ifdef OS_LINUX
    storage_cfg->write_direct_io = iniGetBoolValue(NULL,
            "write_direct_io", ini_ctx->context, false);
    storage_cfg->read_direct_io = iniGetBoolValue(NULL,
            "read_direct_io", ini_ctx->context, false);
#else
    storage_cfg->write_direct_io = false;
    storage_cfg->read_direct_io = false;
#endif

    if ((result=load_write_align_size_from_config(ctx, ini_ctx, 0,
                    &storage_cfg->write_align_size)) != 0)
    {
        return result;
    }

    storage_cfg->fsync_every_n_writes = iniGetIntValue(NULL,
            "fsync_every_n_writes", ini_ctx->context, 0);

    storage_cfg->trunk_allocate_threads = iniGetIntValue(NULL,
            "trunk_allocate_threads", ini_ctx->context, 1);
    if (storage_cfg->trunk_allocate_threads <= 0) {
        storage_cfg->trunk_allocate_threads = 1;
    }

    storage_cfg->max_trunk_files_per_subdir = iniGetIntValue(NULL,
            "max_trunk_files_per_subdir", ini_ctx->context, 100);
    if (storage_cfg->max_trunk_files_per_subdir <= 0) {
        storage_cfg->max_trunk_files_per_subdir = 100;
    }

    storage_cfg->trunk_file_size = iniGetByteCorrectValue(ini_ctx,
            "trunk_file_size", DA_DEFAULT_TRUNK_FILE_SIZE,
            DA_TRUNK_FILE_MIN_SIZE, DA_TRUNK_FILE_MAX_SIZE);
    if (storage_cfg->trunk_file_size <= ctx->storage.file_block_size) {
        logError("file: "__FILE__", line: %d, %s "
                "trunk_file_size: %u is too small, which <= block size %d",
                __LINE__, ctx->module_name, storage_cfg->trunk_file_size,
                ctx->storage.file_block_size);
        return EINVAL;
    }

    storage_cfg->discard_remain_space_size = iniGetByteCorrectValue(
            ini_ctx, "discard_remain_space_size",
            DA_DEFAULT_DISCARD_REMAIN_SPACE_SIZE,
            DA_DISCARD_REMAIN_SPACE_MIN_SIZE,
            DA_DISCARD_REMAIN_SPACE_MAX_SIZE);

    if ((result=iniGetPercentValue(ini_ctx, "reserved_space_per_disk",
                    &storage_cfg->reserved_space_per_disk, 0.10)) != 0)
    {
        return result;
    }

    if ((result=iniGetPercentValue(ini_ctx, "write_cache_to_hd_on_usage",
                    &storage_cfg->write_cache_to_hd.on_usage, 1.00 -
                    storage_cfg->reserved_space_per_disk)) != 0)
    {
        return result;
    }

    if ((result=get_time_item_from_conf(ini_ctx->context,
                    "write_cache_to_hd_start_time", &storage_cfg->
                    write_cache_to_hd.start_time, 0, 0)) != 0)
    {
        return result;
    }
    if ((result=get_time_item_from_conf(ini_ctx->context,
                    "write_cache_to_hd_end_time", &storage_cfg->
                    write_cache_to_hd.end_time, 0, 0)) != 0)
    {
        return result;
    }

    if ((result=iniGetPercentValue(ini_ctx, "reclaim_trunks_on_path_usage",
                    &storage_cfg->reclaim_trunks_on_path_usage, 0.50)) != 0)
    {
        return result;
    }

    if ((result=iniGetPercentValue(ini_ctx, "never_reclaim_on_trunk_usage",
                    &storage_cfg->never_reclaim_on_trunk_usage, 0.90)) != 0)
    {
        return result;
    }

    return load_prealloc_trunks_items(ctx, storage_cfg, ini_ctx);
}

static int load_from_config_file(DAContext *ctx,
        DAStorageConfig *storage_cfg,
        IniFullContext *ini_ctx)
{
    int result;
    if ((result=load_global_items(ctx, storage_cfg, ini_ctx)) != 0) {
        return result;
    }
  
#ifdef OS_LINUX
    if ((result=load_aio_read_buffer_params(storage_cfg, ini_ctx)) != 0) {
        return result;
    }
#endif

    if ((result=load_paths(ctx, storage_cfg, ini_ctx,
                    "store-path", "store_path_count",
                    &storage_cfg->store_path, true)) != 0)
    {
        return result;
    }

    if ((result=load_paths(ctx, storage_cfg, ini_ctx,
                    "write-cache-path", "write_cache_path_count",
                    &storage_cfg->write_cache, false)) != 0)
    {
        return result;
    }

    return 0;
}

static int load_path_indexes(DAContext *ctx, DAStorageConfig *storage_cfg,
        DAStoragePathArray *parray, const char *caption, int *change_count)
{
    int result;
    bool regenerated;
    DAStoragePathInfo *p;
    DAStoragePathInfo *end;
    DAStorePathEntry *pentry;

    end = parray->paths + parray->count;
    for (p=parray->paths; p<end; p++) {
        pentry = da_store_path_index_get(ctx, p->store.path.str);
        if (pentry != NULL) {
            p->store.index = pentry->index;
            if ((result=store_path_check_mark(ctx, pentry,
                            &regenerated)) != 0)
            {
                return result;
            }
            if (regenerated) {
                ++(*change_count);
            }
        } else {
            if ((result=da_store_path_index_add(ctx, p->store.path.str,
                            &p->store.index)) != 0)
            {
                return result;
            }
            ++(*change_count);
        }

#ifdef OS_LINUX
        if (p->write_direct_io || p->read_direct_io) {
            if ((result=get_path_block_size(p->store.path.str,
                            &p->block_size)) != 0)
            {
                return result;
            }

            if (p->write_align_size == 0) {
                if (p->write_direct_io) {
                    p->write_align_size = p->block_size;
                } else {
                    p->write_align_size = 8;
                }
            }
        } else {
            p->block_size = 512;
        }
        p->block_align_mask = p->block_size - 1;
#endif

        if (p->write_align_size == 0) {
            p->write_align_size = 8;
        }
        p->write_align_mask = p->write_align_size - 1;

        if (storage_cfg->discard_remain_space_size < p->write_align_size) {
            storage_cfg->discard_remain_space_size = p->write_align_size;
        }
    }

    return 0;
}

static void do_set_paths_by_index(DAStorageConfig *storage_cfg,
        DAStoragePathArray *parray)
{
    DAStoragePathInfo *p;
    DAStoragePathInfo *end;

    end = parray->paths + parray->count;
    for (p=parray->paths; p<end; p++) {
        storage_cfg->paths_by_index.paths[p->store.index] = p;
    }
}

static int set_paths_by_index(DAStorageConfig *storage_cfg)
{
    int bytes;

    storage_cfg->paths_by_index.count = storage_cfg->max_store_path_index + 1;
    bytes = sizeof(DAStoragePathInfo *) * storage_cfg->paths_by_index.count;
    storage_cfg->paths_by_index.paths = (DAStoragePathInfo **)fc_malloc(bytes);
    if (storage_cfg->paths_by_index.paths == NULL) {
        return ENOMEM;
    }
    memset(storage_cfg->paths_by_index.paths, 0, bytes);

    do_set_paths_by_index(storage_cfg, &storage_cfg->write_cache);
    do_set_paths_by_index(storage_cfg, &storage_cfg->store_path);
    return 0;
}

static int load_store_path_indexes(DAContext *ctx, DAStorageConfig *storage_cfg,
        const char *storage_filename, const bool destroy_store_path_index)
{
    int result;
    int old_count;
    int change_count;

    if ((result=da_store_path_index_init(ctx)) != 0) {
        return result;
    }

    old_count = da_store_path_index_count(ctx);
    change_count = 0;
    do {
        if ((result=load_path_indexes(ctx, storage_cfg, &storage_cfg->
                        write_cache, "write cache paths", &change_count)) != 0)
        {
            break;
        }
        if ((result=load_path_indexes(ctx, storage_cfg, &storage_cfg->
                        store_path, "store paths", &change_count)) != 0)
        {
            break;
        }

    } while (0);

    storage_cfg->max_store_path_index = da_store_path_index_max(ctx);
    if (change_count > 0) {
        int r;
        r = da_store_path_index_save(ctx);
        if (result == 0) {
            result = r;
        }
    }
    if (result == 0) {
        result = set_paths_by_index(storage_cfg);
    }

    logDebug("old_count: %d, new_count: %d, change_count: %d, "
            "max_store_path_index: %d", old_count,
            da_store_path_index_count(ctx), change_count,
            storage_cfg->max_store_path_index);

    if (destroy_store_path_index) {
        da_store_path_index_destroy(ctx);
    }
    return result;
}

int da_storage_config_load(DAContext *ctx, DAStorageConfig *storage_cfg,
        const char *storage_filename, const bool destroy_store_path_index)
{
    IniContext ini_context;
    IniFullContext ini_ctx;
    int result;

    memset(storage_cfg, 0, sizeof(DAStorageConfig));
    if ((result=iniLoadFromFile(storage_filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "load conf file \"%s\" fail, ret code: %d", __LINE__,
                ctx->module_name, storage_filename, result);
        return result;
    }

    FAST_INI_SET_FULL_CTX_EX(ini_ctx, storage_filename, NULL, &ini_context);
    result = load_from_config_file(ctx, storage_cfg, &ini_ctx);
    iniFreeContext(&ini_context);
    if (result == 0) {
        result = load_store_path_indexes(ctx, storage_cfg,
                storage_filename, destroy_store_path_index);
    }
    return result;
}

static void log_paths(DAContext *ctx, DAStoragePathArray *parray,
        const char *caption)
{
    DAStoragePathInfo *p;
    DAStoragePathInfo *end;
    char avail_space_buff[32];
    char reserved_space_buff[32];
    char prealloc_trunks_buff[32];
    char block_size_buff[64];

    if (parray->count == 0) {
        return;
    }

    logInfo("%s %s count: %d", ctx->module_name, caption, parray->count);
    end = parray->paths + parray->count;
    for (p=parray->paths; p<end; p++) {
#ifdef OS_LINUX
        if (p->block_size > 0) {
            sprintf(block_size_buff, ", device block size: %d",
                    p->block_size);
        } else {
            *block_size_buff = '\0';
        }
#else
        *block_size_buff = '\0';
#endif
        long_to_comma_str(p->space_stat.avail /
                (1024 * 1024), avail_space_buff);
        long_to_comma_str(p->reserved_space.value /
                (1024 * 1024), reserved_space_buff);
        long_to_comma_str(p->prealloc_trunks.value /
                (1024 * 1024), prealloc_trunks_buff);
        logInfo("  path %d: %s, index: %d, write_threads: %d, "
                "read_threads: %d, read_io_depth: %d, "
                "write_direct_io: %d, read_direct_io: %d, "
                "write_align_size: %d, fsync_every_n_writes: %d, "
                "prealloc_trunks ratio: %.2f%%, "
                "reserved_space ratio: %.2f%%, "
                "avail_space: %s MB, prealloc_space: %s MB, "
                "reserved_space: %s MB%s",
                (int)(p - parray->paths + 1), p->store.path.str,
                p->store.index, p->write_thread_count,
                p->read_thread_count, p->read_io_depth,
                p->write_direct_io, p->read_direct_io,
                p->write_align_size, p->fsync_every_n_writes,
                p->prealloc_trunks.ratio * 100.00,
                p->reserved_space.ratio * 100.00,
                avail_space_buff, prealloc_trunks_buff,
                reserved_space_buff, block_size_buff
                );
    }
}

void da_storage_config_to_log(DAContext *ctx, DAStorageConfig *storage_cfg)
{
    char prealloc_trunks_buff[256];
    char merge_continuous_slices_buff[64];
    int len;

    len = sprintf(prealloc_trunks_buff, "prealloc-trunks: {enabled: %d",
            storage_cfg->prealloc_trunks.enabled);
    if (storage_cfg->prealloc_trunks.enabled) {
        sprintf(prealloc_trunks_buff + len, ", ratio_per_path: %.2f%%, "
                "start_time: %02d:%02d, end_time: %02d:%02d, threads: %d}",
                storage_cfg->prealloc_trunks.ratio_per_path * 100.00,
                storage_cfg->prealloc_trunks.start_time.hour,
                storage_cfg->prealloc_trunks.start_time.minute,
                storage_cfg->prealloc_trunks.end_time.hour,
                storage_cfg->prealloc_trunks.end_time.minute,
                storage_cfg->prealloc_trunks.threads);
    } else {
        sprintf(prealloc_trunks_buff + len, "}");
    }

    if (ctx->storage.merge_continuous_slices.enabled) {
        sprintf(merge_continuous_slices_buff, "merge_continuous_slices: "
                "{enabled: %d, combine read: %d}, ",
                ctx->storage.merge_continuous_slices.enabled,
                ctx->storage.merge_continuous_slices.combine_read);
    } else {
        *merge_continuous_slices_buff = '\0';
    }
    logInfo("%s storage config, write_threads_per_path: %d, "
            "read_threads_per_path: %d, "
            "io_depth_per_read_thread: %d, "
            "write_direct_io: %d, read_direct_io: %d, "
            "write_align_size: %d, fsync_every_n_writes: %d, "
            "fd_cache_capacity_per_read_thread: %d, "
            "fd_cache_capacity_per_write_thread: %d, "
            "%s, trunk_allocate_threads: %d, %s"
            "reserved_space_per_disk: %.2f%%, "
            "trunk_file_size: %u MB, "
            "max_trunk_files_per_subdir: %d, "
            "discard_remain_space_size: %d, "
#if 0
            / * "write_cache_to_hd: { on_usage: %.2f%%, start_time: %02d:%02d, "
            "end_time: %02d:%02d }, "  */
#endif
            "reclaim_trunks_on_path_usage: %.2f%%, "
#ifdef OS_LINUX
            "never_reclaim_on_trunk_usage: %.2f%%, "
            "memory_watermark_low: %.2f%%, "
            "memory_watermark_high: %.2f%%, "
            "max_idle_time: %d, "
            "reclaim_interval: %d",
#else
            "never_reclaim_on_trunk_usage: %.2f%%",
#endif
            ctx->module_name,
            storage_cfg->write_threads_per_path,
            storage_cfg->read_threads_per_path,
            storage_cfg->io_depth_per_read_thread,
            storage_cfg->write_direct_io,
            storage_cfg->read_direct_io,
            storage_cfg->write_align_size,
            storage_cfg->fsync_every_n_writes,
            storage_cfg->fd_cache_capacity_per_read_thread,
            storage_cfg->fd_cache_capacity_per_write_thread,
            prealloc_trunks_buff, storage_cfg->trunk_allocate_threads,
            merge_continuous_slices_buff,
            storage_cfg->reserved_space_per_disk * 100.00,
            storage_cfg->trunk_file_size / (1024 * 1024),
            storage_cfg->max_trunk_files_per_subdir,
            storage_cfg->discard_remain_space_size,
            /*
            storage_cfg->write_cache_to_hd.on_usage * 100.00,
            storage_cfg->write_cache_to_hd.start_time.hour,
            storage_cfg->write_cache_to_hd.start_time.minute,
            storage_cfg->write_cache_to_hd.end_time.hour,
            storage_cfg->write_cache_to_hd.end_time.minute,
            */
            storage_cfg->reclaim_trunks_on_path_usage * 100.00,
#ifdef OS_LINUX
            storage_cfg->never_reclaim_on_trunk_usage * 100.00,
            storage_cfg->aio_read_buffer.memory_watermark_low.ratio * 100.00,
            storage_cfg->aio_read_buffer.memory_watermark_high.ratio * 100.00,
            storage_cfg->aio_read_buffer.max_idle_time,
            storage_cfg->aio_read_buffer.reclaim_interval
#else
            storage_cfg->never_reclaim_on_trunk_usage * 100.00
#endif
            );

    log_paths(ctx, &storage_cfg->write_cache, "write cache paths");
    log_paths(ctx, &storage_cfg->store_path, "store paths");
}
