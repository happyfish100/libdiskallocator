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
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/uniq_skiplist.h"
#include "sf/sf_global.h"
#include "../binlog/trunk/trunk_binlog.h"
#include "../global.h"
#include "../store_path_index.h"
#include "trunk_id_info.h"

#define TRUNK_ID_DATA_FILENAME_STR ".trunk_id.dat"
#define TRUNK_ID_DATA_FILENAME_LEN (sizeof(TRUNK_ID_DATA_FILENAME_STR) - 1)

#define ITEM_NAME_TRUNK_ID_STR     "trunk_id"
#define ITEM_NAME_TRUNK_ID_LEN     (sizeof(ITEM_NAME_TRUNK_ID_STR) - 1)

#define ITEM_NAME_SUBDIR_ID_STR    "subdir_id"
#define ITEM_NAME_SUBDIR_ID_LEN    (sizeof(ITEM_NAME_SUBDIR_ID_STR) - 1)

#define ITEM_NAME_NORMAL_EXIT_STR  "normal_exit"
#define ITEM_NAME_NORMAL_EXIT_LEN  (sizeof(ITEM_NAME_NORMAL_EXIT_STR) - 1)

typedef struct {
    int subdir;
    int file_count;
} StoreSubdirInfo;

typedef struct {
    UniqSkiplistPair all;
    UniqSkiplistPair freelist;
    pthread_mutex_t lock;
} SortedSubdirs;

typedef struct {
    int count;
    SortedSubdirs *subdirs;  //mapped by store path index
} SortedSubdirArray;

typedef struct da_trunk_id_info_context {
    volatile uint64_t current_trunk_id;
    volatile uint64_t current_subdir_id;
    uint64_t last_trunk_id;
    uint64_t last_subdir_id;
    SortedSubdirArray subdir_array;
} DATrunkIdInfoContext;

static struct fast_mblock_man *subdir_allocator = NULL;

static inline void get_trunk_id_dat_filename(DAContext *ctx,
        char *full_filename, const int size)
{
    fc_get_full_filename_ex(ctx->data.path.str, ctx->data.path.len,
            TRUNK_ID_DATA_FILENAME_STR, TRUNK_ID_DATA_FILENAME_LEN,
            full_filename, size);
}

#define save_current_trunk_id(ctx, current_trunk_id, current_subdir_id) \
    save_current_trunk_id_ex(ctx, current_trunk_id, current_subdir_id, false)

static int save_current_trunk_id_ex(DAContext *ctx,
        const uint64_t current_trunk_id, const uint64_t current_subdir_id,
        const bool on_exit)
{
    char full_filename[PATH_MAX];
    char buff[256];
    char *p;
    int len;
    int result;

    get_trunk_id_dat_filename(ctx, full_filename, sizeof(full_filename));
    p = buff;
    memcpy(p, ITEM_NAME_TRUNK_ID_STR, ITEM_NAME_TRUNK_ID_LEN);
    p += ITEM_NAME_TRUNK_ID_LEN;
    *p++ = '=';
    p += fc_itoa(current_trunk_id, p);
    *p++ = '\n';

    memcpy(p, ITEM_NAME_SUBDIR_ID_STR, ITEM_NAME_SUBDIR_ID_LEN);
    p += ITEM_NAME_SUBDIR_ID_LEN;
    *p++ = '=';
    p += fc_itoa(current_subdir_id, p);
    *p++ = '\n';

    if (on_exit) {
        memcpy(p, ITEM_NAME_NORMAL_EXIT_STR, ITEM_NAME_NORMAL_EXIT_LEN);
        p += ITEM_NAME_NORMAL_EXIT_LEN;
        *p++ = '=';
        *p++ = '1';
        *p++ = '\n';
    }
    len = p - buff;
    if ((result=safeWriteToFile(full_filename, buff, len)) != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "write to file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, ctx->module_name, full_filename,
                result, STRERROR(result));
    }

    return result;
}

static int load_current_trunk_id(DAContext *ctx)
{
    char full_filename[PATH_MAX];
    IniContext ini_context;
    DATrunkIdInfo id_info;
    bool changed;
    int result;

    get_trunk_id_dat_filename(ctx, full_filename, sizeof(full_filename));
    if (access(full_filename, F_OK) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
    }

    if ((result=iniLoadFromFile(full_filename, &ini_context)) != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "load from file \"%s\" fail, error code: %d",
                __LINE__, ctx->module_name, full_filename, result);
        return result;
    }

    ctx->trunk_id_info_ctx->current_trunk_id = iniGetInt64Value(NULL,
            ITEM_NAME_TRUNK_ID_STR, &ini_context, 0);
    ctx->trunk_id_info_ctx->current_subdir_id  = iniGetInt64Value(NULL,
            ITEM_NAME_SUBDIR_ID_STR, &ini_context, 0);

    if (!iniGetBoolValue(NULL, ITEM_NAME_NORMAL_EXIT_STR, &ini_context, false)) {
        if ((result=da_trunk_binlog_get_last_id_info(ctx, &id_info)) != 0) {
            return result;
        }

        changed = false;
        if (id_info.id > ctx->trunk_id_info_ctx->current_trunk_id) {
            changed = true;
            ctx->trunk_id_info_ctx->current_trunk_id = id_info.id;
        }
        if (id_info.subdir > ctx->trunk_id_info_ctx->current_subdir_id) {
            changed = true;
            ctx->trunk_id_info_ctx->current_subdir_id = id_info.subdir;
        }
        if (changed) {
            if ((result=save_current_trunk_id(ctx, ctx->trunk_id_info_ctx->
                            current_trunk_id, ctx->trunk_id_info_ctx->
                            current_subdir_id)) != 0)
            {
                return result;
            }
        }
    }

    iniFreeContext(&ini_context);
    return result;
}

static int compare_by_id(const void *p1, const void *p2)
{
    return ((StoreSubdirInfo *)p1)->subdir -
        ((StoreSubdirInfo *)p2)->subdir;
}

static void id_info_free_func(UniqSkiplist *sl,
        void *ptr, const int delay_seconds)
{
    if (delay_seconds > 0) {
        fast_mblock_delay_free_object(subdir_allocator, ptr, delay_seconds);
    } else {
        fast_mblock_free_object(subdir_allocator, ptr);
    }
}

static int alloc_sorted_subdirs(DAContext *ctx)
{
    int bytes;

    ctx->trunk_id_info_ctx->subdir_array.count = ctx->
        storage.cfg.max_store_path_index + 1;
    bytes = sizeof(SortedSubdirs) * ctx->trunk_id_info_ctx->subdir_array.count;
    ctx->trunk_id_info_ctx->subdir_array.subdirs = fc_malloc(bytes);
    if (ctx->trunk_id_info_ctx->subdir_array.subdirs == NULL) {
        return ENOMEM;
    }
    memset(ctx->trunk_id_info_ctx->subdir_array.subdirs, 0, bytes);
    return 0;
}

static int init_sorted_subdirs(DAContext *ctx, DAStoragePathArray *parray)
{
    const int init_level_count = 4;
    const int max_level_count = 16;
    const int min_alloc_elements_once = 8;
    const int delay_free_seconds = 0;
    int result;
    DAStoragePathInfo *p;
    DAStoragePathInfo *end;
    SortedSubdirs *sorted_subdirs;

    end = parray->paths + parray->count;
    for (p=parray->paths; p<end; p++) {
        sorted_subdirs = ctx->trunk_id_info_ctx->
            subdir_array.subdirs + p->store.index;
        if ((result=uniq_skiplist_init_pair(&sorted_subdirs->all,
                        init_level_count, max_level_count,
                        compare_by_id, id_info_free_func,
                        min_alloc_elements_once, delay_free_seconds)) != 0)
        {
            return result;
        }

        if ((result=uniq_skiplist_init_pair(&sorted_subdirs->freelist,
                        init_level_count, max_level_count, compare_by_id,
                        NULL, min_alloc_elements_once,
                        delay_free_seconds)) != 0)
        {
            return result;
        }

        if ((result=init_pthread_lock(&sorted_subdirs->lock)) != 0) {
            logError("file: "__FILE__", line: %d, %s "
                    "init_pthread_lock fail, errno: %d, error info: %s",
                    __LINE__, ctx->module_name, result, STRERROR(result));
            return result;
        }
    }

    return 0;
}

static int trunk_id_sync_to_file(void *arg)
{
    DAContext *ctx;
    uint64_t current_trunk_id;
    uint64_t current_subdir_id;

    ctx = arg;
    current_trunk_id = __sync_add_and_fetch(
            &ctx->trunk_id_info_ctx->current_trunk_id, 0);
    current_subdir_id = __sync_add_and_fetch(
            &ctx->trunk_id_info_ctx->current_subdir_id, 0);
    if (ctx->trunk_id_info_ctx->last_trunk_id != current_trunk_id ||
            ctx->trunk_id_info_ctx->last_subdir_id != current_subdir_id)
    {
        ctx->trunk_id_info_ctx->last_trunk_id = current_trunk_id;
        ctx->trunk_id_info_ctx->last_subdir_id = current_subdir_id;
        return save_current_trunk_id(ctx, current_trunk_id,
                current_subdir_id);
    }

    return 0;
}

static int setup_sync_to_file_task(DAContext *ctx)
{
    ScheduleEntry schedule_entry;
    ScheduleArray schedule_array;

    INIT_SCHEDULE_ENTRY(schedule_entry, sched_generate_next_id(),
            0, 0, 0, 1, trunk_id_sync_to_file, ctx);

    schedule_array.count = 1;
    schedule_array.entries = &schedule_entry;
    return sched_add_entries(&schedule_array);
}

int da_trunk_id_info_init(DAContext *ctx)
{
    const int alloc_elements_once = 8 * 1024;
    int result;

    ctx->trunk_id_info_ctx = fc_malloc(sizeof(DATrunkIdInfoContext));
    if (ctx->trunk_id_info_ctx == NULL) {
        return ENOMEM;
    }
    memset(ctx->trunk_id_info_ctx, 0, sizeof(DATrunkIdInfoContext));

    if (subdir_allocator == NULL) {
        subdir_allocator = fc_malloc(sizeof(struct fast_mblock_man));
        if (subdir_allocator == NULL) {
            return ENOMEM;
        }
        if ((result=fast_mblock_init_ex1(subdir_allocator, "subdir_info",
                        sizeof(StoreSubdirInfo), alloc_elements_once,
                        0, NULL, NULL, true)) != 0)
        {
            return result;
        }
    }

    if ((result=alloc_sorted_subdirs(ctx)) != 0) {
        return result;
    }
    if ((result=init_sorted_subdirs(ctx, &ctx->storage.cfg.write_cache)) != 0) {
        return result;
    }
    if ((result=init_sorted_subdirs(ctx, &ctx->storage.cfg.store_path)) != 0) {
        return result;
    }

    if ((result=load_current_trunk_id(ctx)) != 0) {
        return result;
    }

    ctx->trunk_id_info_ctx->last_trunk_id = ctx->
        trunk_id_info_ctx->current_trunk_id;
    ctx->trunk_id_info_ctx->last_subdir_id = ctx->
        trunk_id_info_ctx->current_subdir_id;
    return setup_sync_to_file_task(ctx);
}

void da_trunk_id_info_destroy(DAContext *ctx)
{
    uint64_t current_trunk_id;
    uint64_t current_subdir_id;

    current_trunk_id = __sync_add_and_fetch(
            &ctx->trunk_id_info_ctx->current_trunk_id, 0);
    current_subdir_id = __sync_add_and_fetch(
            &ctx->trunk_id_info_ctx->current_subdir_id, 0);
    save_current_trunk_id_ex(ctx, current_trunk_id, current_subdir_id, true);
}

static void da_trunk_id_info_log_noent(DAContext *ctx, const int path_index)
{
    DAStorePathEntry *pentry;

    if ((pentry=da_store_path_index_fetch(ctx, path_index)) == NULL) {
        char path_name[PATH_MAX];
        da_store_path_index_get_filename(ctx, path_name, sizeof(path_name));
        logError("file: "__FILE__", line: %d, %s "
                "store path index: %d not exist in file %s",
                __LINE__, ctx->module_name, path_index, path_name);
    } else {
        logError("file: "__FILE__", line: %d, %s "
                "path: %s, index: %d not in store path list!",
                __LINE__, ctx->module_name, pentry->path, path_index);
    }
}

int da_trunk_id_info_add(DAContext *ctx, const int path_index,
        const DATrunkIdInfo *id_info)
{
    SortedSubdirs *sorted_subdirs;
    StoreSubdirInfo target;
    StoreSubdirInfo *subdir;
    int result;

    target.subdir = id_info->subdir;
    target.file_count = 1;
    result = 0;
    sorted_subdirs = ctx->trunk_id_info_ctx->subdir_array.subdirs + path_index;
    if (sorted_subdirs->all.skiplist == NULL) {
        da_trunk_id_info_log_noent(ctx, path_index);
        return ENOENT;
    }

    PTHREAD_MUTEX_LOCK(&sorted_subdirs->lock);
    do {
        subdir = (StoreSubdirInfo *)uniq_skiplist_find(
                sorted_subdirs->all.skiplist, &target);
        if (subdir != NULL) {
            subdir->file_count++;
            if (subdir->file_count >= ctx->storage.cfg.
                    max_trunk_files_per_subdir)
            {
                uniq_skiplist_delete(sorted_subdirs->
                        freelist.skiplist, subdir);
            }
        } else {
            subdir = fast_mblock_alloc_object(subdir_allocator);
            if (subdir == NULL) {
                result = ENOMEM;
                break;
            }
            *subdir = target;
            if ((result=uniq_skiplist_insert(sorted_subdirs->
                            all.skiplist, subdir)) != 0)
            {
                break;
            }
            if (subdir->file_count < ctx->storage.cfg.
                    max_trunk_files_per_subdir)
            {
                result = uniq_skiplist_insert(sorted_subdirs->
                        freelist.skiplist, subdir);
            }
        }
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&sorted_subdirs->lock);

    return result;
}

int da_trunk_id_info_delete(DAContext *ctx, const int path_index,
        const DATrunkIdInfo *id_info)
{
    SortedSubdirs *sorted_subdirs;
    StoreSubdirInfo target;
    StoreSubdirInfo *subdir;
    int result;

    target.subdir = id_info->subdir;
    target.file_count = 1;
    result = 0;
    sorted_subdirs = ctx->trunk_id_info_ctx->subdir_array.subdirs + path_index;
    if (sorted_subdirs->all.skiplist == NULL) {
        da_trunk_id_info_log_noent(ctx, path_index);
        return ENOENT;
    }

    PTHREAD_MUTEX_LOCK(&sorted_subdirs->lock);
    do {
        subdir = (StoreSubdirInfo *)uniq_skiplist_find(
                sorted_subdirs->all.skiplist, &target);
        if (subdir != NULL) {
            if (subdir->file_count >= ctx->storage.cfg.
                    max_trunk_files_per_subdir)
            {
                uniq_skiplist_insert(sorted_subdirs->
                        freelist.skiplist, subdir);
            }
            subdir->file_count--;
        }
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&sorted_subdirs->lock);

    return result;
}

int da_trunk_id_info_generate(DAContext *ctx,
        const int path_index, DATrunkIdInfo *id_info)
{
    SortedSubdirs *sorted_subdirs;
    StoreSubdirInfo *sd_info;

    sorted_subdirs = ctx->trunk_id_info_ctx->subdir_array.subdirs + path_index;
    if (sorted_subdirs->all.skiplist == NULL) {
        da_trunk_id_info_log_noent(ctx, path_index);
        return ENOENT;
    }

    PTHREAD_MUTEX_LOCK(&sorted_subdirs->lock);
    sd_info = (StoreSubdirInfo *)uniq_skiplist_get_first(
                sorted_subdirs->freelist.skiplist);
    PTHREAD_MUTEX_UNLOCK(&sorted_subdirs->lock);

    if (sd_info != NULL) {
        id_info->subdir = sd_info->subdir;
    } else {
        id_info->subdir = __sync_add_and_fetch(&ctx->
                trunk_id_info_ctx->current_subdir_id, 1);
    }
    id_info->id = __sync_add_and_fetch(&ctx->
            trunk_id_info_ctx->current_trunk_id, 1);

    return 0;
}
