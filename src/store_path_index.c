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

#include <sys/stat.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_buffer.h"
#include "fastcommon/sched_thread.h"
#include "fastcommon/hash.h"
#include "fastcommon/base64.h"
#include "sf/sf_global.h"
#include "global.h"
#include "store_path_index.h"

typedef struct
{
    int server_id;
    int crc32;
    int index;
    time_t create_time;
} StorePathMarkInfo;

#define STORE_PATH_INDEX_FILENAME_STR  ".store_path_index.dat"
#define STORE_PATH_INDEX_FILENAME_LEN  \
    (sizeof(STORE_PATH_INDEX_FILENAME_STR) - 1)

#define STORE_PATH_INDEX_SECTION_PREFIX_STR  "path-"
#define STORE_PATH_INDEX_SECTION_PREFIX_LEN  \
    ((int)sizeof(STORE_PATH_INDEX_SECTION_PREFIX_STR) - 1)

#define STORE_PATH_INDEX_ITEM_PATH_STR     "path"
#define STORE_PATH_INDEX_ITEM_MARK_STR     "mark"
#define STORE_PATH_INDEX_ITEM_MARK_LEN      \
    (sizeof(STORE_PATH_INDEX_ITEM_MARK_STR) - 1)

#define STORE_PATH_MARK_FNAME_STR  ".da_vars"
#define STORE_PATH_MARK_FNAME_LEN  (sizeof(STORE_PATH_MARK_FNAME_STR) - 1)

#define GET_MARK_FULL_FILENAME(path, filename) \
    fc_get_full_filename(path, strlen(path), STORE_PATH_MARK_FNAME_STR, \
            STORE_PATH_MARK_FNAME_LEN, filename);

static int store_path_generate_mark(const char *store_path,
        const int index, char *mark_str)
{
    StorePathMarkInfo mark_info;
    char filename[PATH_MAX];
    char buff[256];
    char *p;
    int mark_len;
    int buff_len;

    mark_info.server_id = DA_MY_SERVER_ID;
    mark_info.index = index;
    mark_info.crc32 = CRC32(store_path, strlen(store_path));
    mark_info.create_time = g_current_time;
    base64_encode_ex(&DA_BASE64_CTX, (char *)&mark_info,
            sizeof(mark_info), mark_str, &mark_len, false);

    GET_MARK_FULL_FILENAME(store_path, filename);
    p = buff;
    memcpy(p, STORE_PATH_INDEX_ITEM_MARK_STR, STORE_PATH_INDEX_ITEM_MARK_LEN);
    p += STORE_PATH_INDEX_ITEM_MARK_LEN;
    *p++ = '=';
    memcpy(p, mark_str, mark_len);
    p += mark_len;
    *p++ = '\n';
    buff_len = p - buff;
    return safeWriteToFile(filename, buff, buff_len);
}

static int store_path_get_mark(DAContext *ctx, const char *filename,
        char *mark, const int size)
{
    IniContext ini_ctx;
    char *value;
    int len;
    int result;

    *mark = '\0';
    if (!fileExists(filename)) {
        return ENOENT;
    }

    if ((result=iniLoadFromFile(filename, &ini_ctx)) != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "load from file \"%s\" fail, error code: %d",
                __LINE__, ctx->module_name, filename, result);
        return result;
    }

    value = iniGetStrValue(NULL, STORE_PATH_INDEX_ITEM_MARK_STR, &ini_ctx);
    if (value != NULL && *value != '\0') {
        len = strlen(value);
        if (len < size) {
            strcpy(mark, value);
        } else {
            logError("file: "__FILE__", line: %d, %s "
                    "mark file: %s, mark length: %d "
                    "is too long exceeds %d", __LINE__,
                    ctx->module_name, filename, len, size);
            result = EOVERFLOW;
        }
    } else {
        result = ENOENT;
    }

    iniFreeContext(&ini_ctx);
    return result;
}

int store_path_check_mark(DAContext *ctx, DAStorePathEntry *pentry,
        bool *regenerated)
{
    StorePathMarkInfo mark_info;
    char filename[PATH_MAX];
    char fs_filename[PATH_MAX];
    char mark[64];
    int mark_len;
    int dest_len;
    int result;

    *regenerated = false;

    GET_MARK_FULL_FILENAME(pentry->path, filename);
    if ((result=store_path_get_mark(ctx, filename,
                    mark, sizeof(mark))) != 0)
    {
        if (result == ENOENT) {
            if (ctx->storage.migrate_path_mark_filename) {
                fc_combine_full_filename(pentry->path, ".fs_vars", fs_filename);
                if (access(fs_filename, F_OK) == 0) {
                    if (rename(fs_filename, filename) != 0) {
                        result = errno != 0 ? errno : EPERM;
                        logError("file: "__FILE__", line: %d, %s "
                                "rename file %s to %s fail, errno: %d, "
                                "error info: %s", __LINE__, ctx->module_name,
                                fs_filename, filename, result, STRERROR(result));
                        return result;
                    }
                    if ((result=store_path_get_mark(ctx, filename,
                                    mark, sizeof(mark))) != 0)
                    {
                        return result;
                    }
                } else {
                    result = errno != 0 ? errno : EPERM;
                    if (result != ENOENT) {
                        logError("file: "__FILE__", line: %d, %s "
                                "access file %s fail, errno: %d, error "
                                "info: %s", __LINE__, ctx->module_name,
                                fs_filename, result, STRERROR(result));
                        return result;
                    }
                }
            }

            if (result == ENOENT) {
                if ((result=store_path_generate_mark(pentry->path,
                                pentry->index, pentry->mark)) == 0)
                {
                    *regenerated = true;
                }
                return result;
            }
        } else {
            return result;
        }
    }

    if (strcmp(mark, pentry->mark) == 0) {
        return 0;
    }

    mark_len = strlen(mark);
    dest_len = (sizeof(StorePathMarkInfo) * 4 + 2) / 3;
    if (mark_len > dest_len) {
        logError("file: "__FILE__", line: %d, %s "
                "the mark length: %d is too long exceed %d, "
                "the mark file: %s, the mark string: %s", __LINE__,
                ctx->module_name, mark_len, dest_len, filename, mark);
        memset(&mark_info, 0, sizeof(StorePathMarkInfo));
    } else if (base64_decode_auto(&DA_BASE64_CTX, mark, mark_len,
                (char *)&mark_info, &dest_len) == NULL)
    {
        logError("file: "__FILE__", line: %d, %s "
                "the mark string is not base64 encoded, "
                "the mark file: %s, the mark string: %s",
                __LINE__, ctx->module_name, filename, mark);
        memset(&mark_info, 0, sizeof(StorePathMarkInfo));
    }

    if (mark_info.server_id > 0) {
        char time_str[32];

        formatDatetime(mark_info.create_time,
                "%Y-%m-%d %H:%M:%S",
                time_str, sizeof(time_str));
        logCrit("file: "__FILE__", line: %d, %s "
                "the store path %s maybe used by other "
                "store server. fields in the mark file: "
                "{ server_id: %d, path_index: %d, crc32: %d,"
                " create_time: %s }, if you confirm that it is NOT "
                "used by other store server, you can delete the mark "
                "file %s then try again.", __LINE__, ctx->module_name,
                pentry->path, mark_info.server_id, mark_info.index,
                mark_info.crc32, time_str, filename);
    } else {
        logCrit("file: "__FILE__", line: %d, %s "
                "the store path %s maybe used by other "
                "store server. if you confirm that it is NOT "
                "used by other storage server, you can delete "
                "the mark file %s then try again", __LINE__,
                ctx->module_name, pentry->path, filename);
    }

    return EINVAL;
}

const char *da_store_path_index_get_filename(DAContext *ctx,
        char *full_filename, const int size)
{
    fc_get_full_filename_ex(ctx->data.path.str, ctx->data.path.len,
            STORE_PATH_INDEX_FILENAME_STR, STORE_PATH_INDEX_FILENAME_LEN,
            full_filename, size);
    return full_filename;
}

static int check_alloc_store_paths(DAContext *ctx, const int inc_count)
{
    int alloc;
    int target_count;
    int bytes;
    DAStorePathEntry *entries;

    target_count = ctx->store_path_array.count + inc_count;
    if (ctx->store_path_array.alloc >= target_count) {
        return 0;
    }

    if (ctx->store_path_array.alloc == 0) {
        alloc = 8;
    } else {
        alloc = ctx->store_path_array.alloc * 2;
    }

    while (alloc < target_count) {
        alloc *= 2;
    }

    bytes = sizeof(DAStorePathEntry) * alloc;
    entries = (DAStorePathEntry *)fc_malloc(bytes);
    if (entries == NULL) {
        return ENOMEM;
    }

    if (ctx->store_path_array.entries != NULL) {
        memcpy(entries, ctx->store_path_array.entries,
                sizeof(DAStorePathEntry) * ctx->store_path_array.count);
        free(ctx->store_path_array.entries);
    }

    ctx->store_path_array.entries = entries;
    ctx->store_path_array.alloc = alloc;
    return 0;
}

static int load_one_store_path_index(DAContext *ctx, IniContext *ini_ctx,
        char *full_filename, IniSectionInfo *section, DAStorePathEntry *pentry)
{
    char *index_str;
    char *path;
    char *mark;
    char *endptr;

    index_str = section->section_name + STORE_PATH_INDEX_SECTION_PREFIX_LEN;
    pentry->index = strtol(index_str, &endptr, 10);
    if (*endptr != '\0') {
        logError("file: "__FILE__", line: %d, %s "
                "data file: %s, section: %s, index is invalid", __LINE__,
                ctx->module_name, full_filename, section->section_name);
        return EINVAL;
    }

    path = iniGetStrValue(section->section_name, "path", ini_ctx);
    if (path == NULL) {
        logError("file: "__FILE__", line: %d, %s "
                "data file: %s, section: %s, item \"path\" not exist",
                __LINE__, ctx->module_name, full_filename,
                section->section_name);
        return ENOENT;
    }

    mark = iniGetStrValue(section->section_name, "mark", ini_ctx);
    if (mark == NULL) {
        logError("file: "__FILE__", line: %d, %s "
                "data file: %s, section: %s, item \"mark\" not exist",
                __LINE__, ctx->module_name, full_filename,
                section->section_name);
        return ENOENT;
    }

    fc_safe_strcpy(pentry->path, path);
    fc_safe_strcpy(pentry->mark, mark);
    return 0;
}

static int compare_store_path_index(const void *p1, const void *p2)
{
    return ((DAStorePathEntry *)p1)->index - ((DAStorePathEntry *)p2)->index;
}

static int load_store_path_index(DAContext *ctx,
        IniContext *ini_ctx, char *full_filename)
{
#define FIXED_SECTION_COUNT 64
    int result;
    int alloc_size;
    int count;
    int bytes;
    IniSectionInfo fixed_sections[FIXED_SECTION_COUNT];
    IniSectionInfo *sections;
    IniSectionInfo *section;
    IniSectionInfo *end;
    DAStorePathEntry *pentry;

    sections = fixed_sections;
    alloc_size = FIXED_SECTION_COUNT;
    result = iniGetSectionNamesByPrefix(ini_ctx,
            STORE_PATH_INDEX_SECTION_PREFIX_STR, sections,
            alloc_size, &count);
    if (result == ENOSPC) {
        sections = NULL;
        do {
            alloc_size *= 2;
            bytes = sizeof(IniSectionInfo) * alloc_size;
            sections = (IniSectionInfo *)fc_realloc(sections, bytes);
            if (sections == NULL) {
                return ENOMEM;
            }
            result = iniGetSectionNamesByPrefix(ini_ctx,
                    STORE_PATH_INDEX_SECTION_PREFIX_STR, sections,
                    alloc_size, &count);
        } while (result == ENOSPC);
    }

    if (result != 0) {
        return result;
    }

    if ((result=check_alloc_store_paths(ctx, count)) != 0) {
        return result;
    }

    pentry = ctx->store_path_array.entries;
    end = sections + count;
    for (section=sections; section<end; section++,pentry++) {
        if ((result=load_one_store_path_index(ctx, ini_ctx,
                        full_filename, section, pentry)) != 0)
        {
            return result;
        }
    }
    ctx->store_path_array.count = count;

    if (ctx->store_path_array.count > 1) {
        qsort(ctx->store_path_array.entries, ctx->store_path_array.count,
                sizeof(DAStorePathEntry), compare_store_path_index);
    }

    if (sections != fixed_sections) {
        free(sections);
    }
    return 0;
}

int da_store_path_index_count(DAContext *ctx)
{
    return ctx->store_path_array.count;
}

int da_store_path_index_max(DAContext *ctx)
{
    if (ctx->store_path_array.count > 0) {
        return ctx->store_path_array.entries[ctx->
            store_path_array.count - 1].index;
    } else {
        return 0;
    }
}

int da_store_path_index_init(DAContext *ctx)
{
    int result;
    IniContext ini_ctx;
    char full_filename[PATH_MAX];

    da_store_path_index_get_filename(ctx, full_filename, sizeof(full_filename));
    if (access(full_filename, F_OK) != 0) {
        if (errno == ENOENT) {
            return 0;
        }

        result = errno != 0 ? errno : EPERM;
        logError("file: "__FILE__", line: %d, %s "
                "access file %s fail, errno: %d, error info: %s",
                __LINE__, ctx->module_name, full_filename,
                result, STRERROR(result));
        return result;
    }

    if ((result=iniLoadFromFile(full_filename, &ini_ctx)) != 0) {
        logError("file: "__FILE__", line: %d, %s "
                "load conf file \"%s\" fail, ret code: %d", __LINE__,
                ctx->module_name, full_filename, result);
        return result;
    }

    result = load_store_path_index(ctx, &ini_ctx, full_filename);
    iniFreeContext(&ini_ctx);
    return result;
}

void da_store_path_index_destroy(DAContext *ctx)
{
    if (ctx->store_path_array.entries != NULL) {
        free(ctx->store_path_array.entries);
        ctx->store_path_array.entries = NULL;
        ctx->store_path_array.count = ctx->store_path_array.alloc = 0;
    }
}

DAStorePathEntry *da_store_path_index_get(
        DAContext *ctx, const char *path)
{
    DAStorePathEntry *entry;

    if (ctx->store_path_array.count == 0) {
        return NULL;
    }

    for (entry=ctx->store_path_array.entries + ctx->store_path_array.count - 1;
            entry>=ctx->store_path_array.entries; entry--)
    {
        if (strcmp(path, entry->path) == 0) {
            return entry;
        }
    }

    return NULL;
}

DAStorePathEntry *da_store_path_index_fetch(
        DAContext *ctx, const int index)
{
    DAStorePathEntry target;

    if (ctx->store_path_array.entries == NULL) {
        if (da_store_path_index_init(ctx) != 0) {
            return NULL;
        }
    }

    target.index = index;
    return bsearch(&target, ctx->store_path_array.entries,
            ctx->store_path_array.count, sizeof(DAStorePathEntry),
            compare_store_path_index);
}

int da_store_path_index_add(DAContext *ctx,
        const char *path, int *index)
{
    int result;
    char filename[PATH_MAX];
    char mark[64];
    DAStorePathEntry *pentry;

    if ((result=check_alloc_store_paths(ctx, 1)) != 0) {
        return result;
    }

    if (ctx->store_path_array.count > 0) {
        *index = ctx->store_path_array.entries[ctx->
            store_path_array.count - 1].index + 1;
    } else {
        *index = 0;
    }

    pentry = ctx->store_path_array.entries + ctx->store_path_array.count;
    GET_MARK_FULL_FILENAME(path, filename);
    result = store_path_get_mark(ctx, filename, mark, sizeof(mark));
    if (result != ENOENT) {
        if (result == 0) {
            logCrit("file: "__FILE__", line: %d, %s "
                    "store path: %s, the mark file %s already exist, "
                    "if you confirm that it is NOT used by other store "
                    "server, you can delete this mark file then try again.",
                    __LINE__, ctx->module_name, path, filename);
            return EEXIST;
        }
        return result;
    }

    if ((result=store_path_generate_mark(path, *index, pentry->mark)) != 0) {
        return result;
    }

    pentry->index = *index;
    fc_safe_strcpy(pentry->path, path);
    ctx->store_path_array.count++;
    return 0;
}

int da_store_path_index_save(DAContext *ctx)
{
    int result;
    FastBuffer buffer;
    DAStorePathEntry *pentry;
    DAStorePathEntry *end;
    char full_filename[PATH_MAX];

    if ((result=fast_buffer_init1(&buffer, 128 * ctx->
                    store_path_array.count)) != 0)
    {
        return result;
    }

    end  = ctx->store_path_array.entries + ctx->store_path_array.count;
    for (pentry=ctx->store_path_array.entries; pentry<end; pentry++) {
        result = fast_buffer_append(&buffer,
                "[%s%d]\n"
                "%s=%s\n"
                "%s=%s\n\n",
                STORE_PATH_INDEX_SECTION_PREFIX_STR, pentry->index,
                STORE_PATH_INDEX_ITEM_PATH_STR, pentry->path,
                STORE_PATH_INDEX_ITEM_MARK_STR, pentry->mark);
        if (result != 0) {
            return result;
        }
    }

    da_store_path_index_get_filename(ctx, full_filename, sizeof(full_filename));
    result = safeWriteToFile(full_filename, buffer.data, buffer.length);

    fast_buffer_destroy(&buffer);
    return result;
}
