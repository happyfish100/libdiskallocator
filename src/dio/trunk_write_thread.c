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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/uniq_skiplist.h"
#include "sf/sf_global.h"
#include "sf/sf_func.h"
#include "../binlog/trunk/trunk_binlog.h"
#include "trunk_fd_cache.h"
#include "trunk_write_thread.h"

static void *da_trunk_write_thread_func(void *arg);

static int alloc_path_contexts(DAContext *ctx)
{
    int count;
    int bytes;

    count = ctx->storage.cfg.max_store_path_index + 1;
    bytes = sizeof(TrunkWriteContext) + sizeof(TrunkWritePathContext) * count;
    ctx->trunk_write_ctx = fc_malloc(bytes);
    if (ctx->trunk_write_ctx == NULL) {
        return ENOMEM;
    }
    memset(ctx->trunk_write_ctx, 0, bytes);
    ctx->trunk_write_ctx->path_ctx_array.count = count;
    ctx->trunk_write_ctx->path_ctx_array.paths = (TrunkWritePathContext *)
        (ctx->trunk_write_ctx + 1);
    return 0;
}

static TrunkWriteThreadContext *alloc_thread_contexts(const int count)
{
    TrunkWriteThreadContext *contexts;
    int bytes;

    bytes = sizeof(TrunkWriteThreadContext) * count;
    contexts = (TrunkWriteThreadContext *)fc_malloc(bytes);
    if (contexts == NULL) {
        return NULL;
    }
    memset(contexts, 0, bytes);
    return contexts;
}

static int trunk_write_thread_push_compare(const TrunkWriteIOBuffer *iob1,
        const TrunkWriteIOBuffer *iob2)
{
    return fc_compare_int64(iob1->version, iob2->version);
}

static int trunk_write_thread_pop_compare(
        const TrunkWriteIOBuffer *iob,
        const TrunkWriteIOBuffer *less_equal,
        TrunkWriteThreadContext *thread)
{
    int distance;
    int log_level;

    if (iob->version == thread->last_version + 1) {
        thread->last_version = iob->version;
        return -1;
    } else {
        distance = iob->version - thread->last_version;
        if (distance < 0) {
            log_level = LOG_ERR;
        } else if (distance > 256) {
            log_level = LOG_WARNING;
        } else {
            log_level = LOG_DEBUG;
        }
        log_it_ex(&g_log_context, log_level,
                "file: "__FILE__", line: %d, %s, "
                "path index: %d, thread index: %d, iob version: %"PRId64", "
                "queue last version: %"PRId64", expect iob count: %d",
                __LINE__, thread->ctx->module_name, thread->indexes.path,
                thread->indexes.thread >= 0 ?  thread->indexes.thread : 0,
                iob->version, thread->last_version, distance);
        return 1;
    }
}

static int init_write_context(TrunkWriteThreadContext *thread)
{
    int result;

    if ((result=fc_check_realloc_iovec_array(&thread->
                    iovec_array, IOV_MAX)) != 0)
    {
        return result;
    }

    thread->iob_array.alloc = IOV_MAX;
    thread->iob_array.iobs = fc_malloc(sizeof(TrunkWriteIOBuffer *) *
            thread->iob_array.alloc);
    if (thread->iob_array.iobs == NULL) {
        return ENOMEM;
    }

    if (thread->path_info->write_direct_io) {
        thread->write_bytes_max = 8 * 1024 * 1024;
        thread->direct_io.buffer.buff = NULL;
        thread->direct_io.buffer.alloc_size = FC_MAX(thread->ctx->storage.
                file_block_size, thread->path_info->block_size);
        if (thread->direct_io.buffer.alloc_size < thread->write_bytes_max) {
            thread->direct_io.buffer.alloc_size = thread->write_bytes_max;
        }
        thread->direct_io.buffer.alloc_size = MEM_ALIGN_CEIL_BY_MASK(
                thread->direct_io.buffer.alloc_size,
                thread->path_info->block_align_mask);
        if ((result=posix_memalign((void **)&thread->direct_io.buffer.buff,
                    thread->path_info->block_size, thread->direct_io.buffer.
                    alloc_size)) != 0)
        {
            logError("file: "__FILE__", line: %d, %s "
                    "posix_memalign %d bytes fail, block size: %d, errno: %d, "
                    "error info: %s", __LINE__, thread->ctx->module_name,
                    thread->direct_io.buffer.alloc_size, thread->path_info->
                    block_size, result, STRERROR(result));
            return result;
        }
        thread->direct_io.buffer.end = thread->direct_io.buffer.buff +
            thread->direct_io.buffer.alloc_size;

#ifdef OS_LINUX
        thread->file_handle.write_flags = O_WRONLY | O_DIRECT | O_CLOEXEC;
        thread->direct_io.file.read_flags = O_RDONLY | O_DIRECT | O_CLOEXEC;
#else
        thread->file_handle.write_flags = O_WRONLY | O_CLOEXEC;
        thread->direct_io.file.read_flags = O_RDONLY | O_CLOEXEC;
#endif
    } else {
        thread->write_bytes_max = 64 * 1024 * 1024;
        thread->file_handle.write_flags = O_WRONLY | O_CLOEXEC;
    }

    return 0;
}

static int init_thread_context(TrunkWriteThreadContext *thread)
{
    int result;
    pthread_t tid;

    if ((result=fast_mblock_init_ex1(&thread->mblock, "trunk-write-buffer",
                    sizeof(TrunkWriteIOBuffer), 4 * 1024, 0, NULL,
                    NULL, true)) != 0)
    {
        return result;
    }

    if ((result=sorted_queue_init(&thread->queue, (long)
                    (&((TrunkWriteIOBuffer *)NULL)->dlink),
                    (int (*)(const void *, const void *))
                    trunk_write_thread_push_compare,
                    (int (*)(const void *, const void *, void *))
                    trunk_write_thread_pop_compare, thread)) != 0)
    {
        return result;
    }

    thread->less_than.version = INT64_MAX;
    thread->file_handle.trunk_id = 0;
    thread->file_handle.fd = -1;
    if ((result=init_write_context(thread)) != 0) {
        return result;
    }
    return fc_create_thread(&tid, da_trunk_write_thread_func,
            thread, SF_G_THREAD_STACK_SIZE);
}

static int init_thread_contexts(DAContext *ctx,
        TrunkWriteThreadContextArray *ctx_array,
        const int path_index)
{
    int result;
    TrunkWriteThreadContext *thread;
    TrunkWriteThreadContext *end;

    end = ctx_array->contexts + ctx_array->count;
    for (thread=ctx_array->contexts; thread<end; thread++) {
        thread->ctx = ctx;
        thread->indexes.path = path_index;
        if (ctx_array->count == 1) {
            thread->indexes.thread = -1;
        } else {
            thread->indexes.thread = thread - ctx_array->contexts;
        }
        thread->path_info = ctx->storage.cfg.paths_by_index.paths[path_index];
        if ((result=init_thread_context(thread)) != 0) {
            return result;
        }
    }

    return 0;
}

static int init_path_contexts(DAContext *ctx, DAStoragePathArray *parray)
{
    DAStoragePathInfo *p;
    DAStoragePathInfo *end;
    TrunkWriteThreadContext *thread_ctxs;
    TrunkWritePathContext *path_ctx;
    int result;

    end = parray->paths + parray->count;
    for (p=parray->paths; p<end; p++) {
        path_ctx = ctx->trunk_write_ctx->path_ctx_array.
            paths + p->store.index;
        if ((thread_ctxs=alloc_thread_contexts(p->
                        write_thread_count)) == NULL)
        {
            return ENOMEM;
        }

        path_ctx->writes.contexts = thread_ctxs;
        path_ctx->writes.count = p->write_thread_count;
        if ((result=init_thread_contexts(ctx, &path_ctx->
                        writes, p->store.index)) != 0)
        {
            return result;
        }
    }

    return 0;
}

int da_trunk_write_thread_init(DAContext *ctx)
{
    int result;

    if ((result=alloc_path_contexts(ctx)) != 0) {
        return result;
    }

    if ((result=init_path_contexts(ctx, &ctx->storage.cfg.write_cache)) != 0) {
        return result;
    }
    if ((result=init_path_contexts(ctx, &ctx->storage.cfg.store_path)) != 0) {
        return result;
    }

    /*
       logInfo("%s ctx->trunk_write_ctx->path_ctx_array.count: %d",
               ctx->module_name, ctx->trunk_write_ctx->path_ctx_array.count);
     */
    return 0;
}

void da_trunk_write_thread_terminate(DAContext *ctx)
{
    TrunkWritePathContext *path_ctx;
    TrunkWritePathContext *path_end;
    TrunkWriteThreadContext *thread_ctx;
    TrunkWriteThreadContext *thread_end;
    TrunkWriteIOBuffer *iob;
    int running_threads;

    running_threads = FC_ATOMIC_GET(ctx->trunk_write_ctx->running_threads);
    if (running_threads == 0) {
        return;
    }

    logInfo("file: "__FILE__", line: %d, %s "
            "waiting trunk write threads exit, running threads: %d",
            __LINE__, ctx->module_name, running_threads);

    path_end = ctx->trunk_write_ctx->path_ctx_array.paths +
        ctx->trunk_write_ctx->path_ctx_array.count;
    for (path_ctx=ctx->trunk_write_ctx->path_ctx_array.paths;
            path_ctx<path_end; path_ctx++)
    {
        thread_end = path_ctx->writes.contexts + path_ctx->writes.count;
        for (thread_ctx=path_ctx->writes.contexts;
                thread_ctx<thread_end; thread_ctx++)
        {
            if ((iob=fast_mblock_alloc_object(&thread_ctx->mblock)) != NULL) {
                memset(iob, 0, sizeof(*iob));
                iob->op_type = DA_IO_TYPE_QUIT;
                iob->version = __sync_add_and_fetch(
                        &thread_ctx->current_version, 1);
                sorted_queue_push(&thread_ctx->queue, iob);
            }
        }
    }

    while (FC_ATOMIC_GET(ctx->trunk_write_ctx->running_threads) > 0) {
        fc_sleep_ms(10);
    }

    logInfo("file: "__FILE__", line: %d, %s "
            "trunk write threads exit",
            __LINE__, ctx->module_name);
}

static inline TrunkWriteIOBuffer *alloc_init_buffer(DAContext *ctx,
        TrunkWriteThreadContext **thread_ctx, const int op_type,
        const int64_t version, const DATrunkSpaceInfo *space,
        void *data)
{
    TrunkWriteIOBuffer *iob;

    *thread_ctx = da_trunk_write_thread_get(ctx, space);
    iob = fast_mblock_alloc_object(&(*thread_ctx)->mblock);
    if (iob == NULL) {
        return NULL;
    }

    iob->op_type = op_type;
    iob->version = version;
    iob->space = *space;
    if (op_type == DA_IO_TYPE_WRITE_SLICE_BY_IOVEC) {
        iob->iovec_array = *((iovec_array_t *)data);
    } else {
        iob->buff = (char *)data;
    }

    return iob;
}

int da_trunk_write_thread_push(DAContext *ctx, const int op_type,
        const int64_t version, const DATrunkSpaceInfo *space,
        void *data, da_trunk_write_io_notify_func notify_func,
        void *arg1, void *arg2)
{
    TrunkWriteThreadContext *thread_ctx;
    TrunkWriteIOBuffer *iob;

    if ((iob=alloc_init_buffer(ctx, &thread_ctx, op_type,
                    version, space, data)) == NULL)
    {
        return ENOMEM;
    }

    iob->slice_type = DA_SLICE_TYPE_FILE;
    iob->notify.func = notify_func;
    iob->notify.arg1 = arg1;
    iob->notify.arg2 = arg2;
    sorted_queue_push(&thread_ctx->queue, iob);
    return 0;
}

int da_trunk_write_thread_push_cached_slice(DAContext *ctx,
        const int op_type, const int64_t version,
        const DATrunkSpaceInfo *space, void *data,
        const DASliceEntry *slice, void *arg)
{
    TrunkWriteThreadContext *thread_ctx;
    TrunkWriteIOBuffer *iob;

    if ((iob=alloc_init_buffer(ctx, &thread_ctx, op_type,
                    version, space, data)) == NULL)
    {
        return ENOMEM;
    }

    iob->slice_type = DA_SLICE_TYPE_CACHE;
    iob->slice = *slice;
    iob->arg = arg;
    sorted_queue_push(&thread_ctx->queue, iob);
    return 0;
}

static inline void close_write_fd(TrunkWriteThreadContext *ctx)
{
#ifdef OS_LINUX
    if (ctx->path_info->read_direct_io && !ctx->path_info->write_direct_io) {
        posix_fadvise(ctx->file_handle.fd, 0, 0, POSIX_FADV_DONTNEED);
    }
#endif

    close(ctx->file_handle.fd);
}

static inline void clear_write_fd(TrunkWriteThreadContext *ctx)
{
    if (ctx->file_handle.fd >= 0) {
        close_write_fd(ctx);
        ctx->file_handle.fd = -1;
        ctx->file_handle.trunk_id = 0;
    }
}

static int get_write_fd(TrunkWriteThreadContext *thread,
        DATrunkSpaceInfo *space, int *fd)
{
    char trunk_filename[PATH_MAX];
    int result;

    if (space->id_info.id == thread->file_handle.trunk_id) {
        *fd = thread->file_handle.fd;
        return 0;
    }

    dio_get_trunk_filename(space, trunk_filename, sizeof(trunk_filename));
    *fd = open(trunk_filename, thread->file_handle.write_flags, 0644);
    if (*fd < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, thread->path_info->ctx->module_name,
                trunk_filename, result, STRERROR(result));
        return result;
    }

    if (thread->file_handle.fd >= 0) {
        close_write_fd(thread);
    }

    thread->file_handle.trunk_id = space->id_info.id;
    thread->file_handle.fd = *fd;
    thread->file_handle.offset = 0;
    return 0;
}

static int do_create_trunk(TrunkWriteThreadContext *thread,
        TrunkWriteIOBuffer *iob)
{
    char trunk_filename[PATH_MAX];
    int fd;
    int result;

    dio_get_trunk_filename(&iob->space, trunk_filename, sizeof(trunk_filename));
    fd = open(trunk_filename, thread->file_handle.write_flags | O_CREAT, 0644);
    if (fd < 0) {
        if (errno == ENOENT) {
            char filepath[PATH_MAX];
            char *pend;
            int len;

            pend = strrchr(trunk_filename, '/');
            len = pend - trunk_filename;
            memcpy(filepath, trunk_filename, len);
            *(filepath + len) = '\0';
            if (mkdir(filepath, 0755) < 0) {
                result = errno != 0 ? errno : EACCES;
                logError("file: "__FILE__", line: %d, %s "
                        "mkdir \"%s\" fail, errno: %d, error info: %s",
                        __LINE__, thread->path_info->ctx->module_name,
                        filepath, result, STRERROR(result));
                return result;
            }
            fd = open(trunk_filename, thread->file_handle.
                    write_flags | O_CREAT, 0644);
        }
    }

    if (fd < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, thread->path_info->ctx->module_name,
                trunk_filename, result, STRERROR(result));
        return result;
    }

    if (fc_fallocate(fd, iob->space.size) == 0) {
        result = da_trunk_binlog_write(thread->ctx, DA_IO_TYPE_CREATE_TRUNK,
                iob->space.store->index, &iob->space.id_info,
                iob->space.size);
    } else {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "ftruncate file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, thread->path_info->ctx->module_name,
                trunk_filename, result, STRERROR(result));
    }

    close(fd);
    return result;
}

static int do_delete_trunk(TrunkWriteThreadContext *thread,
        TrunkWriteIOBuffer *iob)
{
    char trunk_filename[PATH_MAX];
    int result;

    dio_get_trunk_filename(&iob->space, trunk_filename, sizeof(trunk_filename));
    if (unlink(trunk_filename) == 0) {
        result = da_trunk_binlog_write(thread->ctx, DA_IO_TYPE_DELETE_TRUNK,
                iob->space.store->index, &iob->space.id_info,
                iob->space.size);
    } else {
        result = errno != 0 ? errno : EACCES;
        if (result == ENOENT) {
            result = 0;
        } else {
            logError("file: "__FILE__", line: %d, %s "
                    "trunk_filename file \"%s\" fail, errno: %d, error info: %s",
                    __LINE__, thread->path_info->ctx->module_name,
                    trunk_filename, result, STRERROR(result));
        }
    }

    return result;
}

static int write_iovec(int fd, struct iovec *iovec,
        int iovcnt, int *remain_bytes)
{
    struct iovec *iov;
    struct iovec *end;
    int write_bytes;
    int iov_sum;
    int iov_remain;
    int result;

    iov = iovec;
    end = iovec + iovcnt;
    while (iovcnt > 0) {
        if ((write_bytes=writev(fd, iov, iovcnt)) < 0) {
            result = errno != 0 ? errno : EIO;
            if (result == EINTR) {
                continue;
            }

            return result;
        }

        *remain_bytes -= write_bytes;
        if (*remain_bytes == 0) {
            break;
        }

        iov_sum = 0;
        do {
            iov_sum += iov->iov_len;
            iov_remain = iov_sum - write_bytes;
            if (iov_remain == 0) {
                iov++;
                break;
            } else if (iov_remain > 0) {
                iov->iov_base += (iov->iov_len - iov_remain);
                iov->iov_len = iov_remain;
                break;
            }

            iov++;
        } while (iov < end);

        iovcnt = end - iov;
    }

    return 0;
}

static int do_write_slices(TrunkWriteThreadContext *thread)
{
    char trunk_filename[PATH_MAX];
    TrunkWriteIOBuffer *first;
    struct iovec *iovec;
    int iovcnt;
    int fd;
    uint32_t offset;
    int remain_count;
    int remain_bytes;
    int padding_bytes;
    int write_bytes;
    int result;

    first = thread->iob_array.iobs[0];
    if ((result=get_write_fd(thread, &first->space, &fd)) != 0) {
        thread->iob_array.success = 0;
        return result;
    }

    if (thread->path_info->write_direct_io) {
        offset = thread->direct_io.file.first_offset;
    } else {
        offset = first->space.offset;
    }
    if (thread->file_handle.offset != offset) {
        if (lseek(fd, offset, SEEK_SET) < 0) {
            dio_get_trunk_filename(&first->space, trunk_filename,
                    sizeof(trunk_filename));
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, %s "
                    "lseek file: %s fail, offset: %u, "
                    "errno: %d, error info: %s", __LINE__, thread->
                    path_info->ctx->module_name, trunk_filename,
                    offset, result, STRERROR(result));
            clear_write_fd(thread);
            thread->iob_array.success = 0;
            return result;
        }
    }

    if (thread->path_info->write_direct_io) {
        thread->iovec_bytes = thread->direct_io.buffer.last -
            thread->direct_io.buffer.buff;
        remain_bytes = (thread->iovec_bytes & thread->
                path_info->block_align_mask);
        if (remain_bytes != 0) {
            padding_bytes = thread->path_info->block_size - remain_bytes;
            memset(thread->direct_io.buffer.last, 0, padding_bytes);
            thread->direct_io.buffer.last += padding_bytes;
            thread->iovec_bytes += padding_bytes;
        }

        if ((write_bytes=write(fd, thread->direct_io.buffer.buff,
                        thread->iovec_bytes)) == thread->iovec_bytes)
        {
            result = 0;
        } else {
            result = errno != 0 ? errno : EIO;
            remain_bytes = (write_bytes <= 0 ? thread->iovec_bytes :
                    thread->iovec_bytes - write_bytes);
        }
    } else {
        remain_bytes = thread->iovec_bytes;
        if (thread->iovec_array.count <= IOV_MAX) {
            result = write_iovec(fd, thread->iovec_array.iovs,
                    thread->iovec_array.count, &remain_bytes);
        } else {
            iovec = thread->iovec_array.iovs;
            remain_count = thread->iovec_array.count;
            while (remain_count > 0) {
                iovcnt = (remain_count < IOV_MAX ? remain_count : IOV_MAX);
                if ((result=write_iovec(fd, iovec, iovcnt,
                                &remain_bytes)) != 0)
                {
                    break;
                }

                remain_count -= iovcnt;
                iovec += iovcnt;
            }
        }
    }

    thread->written_count++;
    if (result == 0) {
        if (thread->path_info->fsync_every_n_writes > 0 &&
                thread->written_count % thread->path_info->
                fsync_every_n_writes == 0)
        {
            if (fsync(fd) != 0) {
                result = errno != 0 ? errno : EIO;
                logError("file: "__FILE__", line: %d, %s "
                        "sync to trunk file: %s fail, "
                        "errno: %d, error info: %s", __LINE__,
                        thread->path_info->ctx->module_name,
                        trunk_filename, result, STRERROR(result));
            }
        }
    }

    if (result != 0) {
        clear_write_fd(thread);

        dio_get_trunk_filename(&first->space, trunk_filename,
                sizeof(trunk_filename));
        logError("file: "__FILE__", line: %d, %s "
                "write to trunk file: %s fail, offset: %u, "
                "errno: %d, error info: %s", __LINE__,
                thread->path_info->ctx->module_name, trunk_filename,
                offset + (thread->iovec_bytes - remain_bytes),
                result, STRERROR(result));
        thread->file_handle.offset = -1;
        thread->iob_array.success = 0;
        return result;
    }

    thread->iob_array.success = thread->iob_array.count;
    thread->file_handle.offset = offset + thread->iovec_bytes;
    return 0;
}

static inline void add_to_batch_free_chain(TrunkWriteThreadContext *thread,
        TrunkWriteIOBuffer *iob)
{
    struct fast_mblock_node *node;

    node = fast_mblock_to_node_ptr(iob);
    if (thread->batch_free_chain.head == NULL) {
        thread->batch_free_chain.head = node;
    } else {
        thread->batch_free_chain.tail->next = node;
    }
    thread->batch_free_chain.tail = node;
}

static int batch_write(TrunkWriteThreadContext *thread)
{
    int result;
    TrunkWriteIOBuffer **iob;
    TrunkWriteIOBuffer **end;

    result = do_write_slices(thread);
    iob = thread->iob_array.iobs;
    if (thread->iob_array.success > 0) {
        end = thread->iob_array.iobs + thread->iob_array.success;
        for (; iob < end; iob++) {
            if ((*iob)->slice_type == DA_SLICE_TYPE_CACHE) {
                thread->ctx->cached_slice_write_done(&(*iob)->slice,
                        &(*iob)->space, (*iob)->arg);
            } else if ((*iob)->notify.func != NULL) {
                (*iob)->notify.func(*iob, 0);
            }

            add_to_batch_free_chain(thread, *iob);
        }
    }

    if (result != 0) {
        end = thread->iob_array.iobs + thread->iob_array.count;
        for (; iob < end; iob++) {
            if ((*iob)->slice_type != DA_SLICE_TYPE_CACHE &&
                    (*iob)->notify.func != NULL)
            {
                (*iob)->notify.func(*iob, result);
            }

            add_to_batch_free_chain(thread, *iob);
        }

        sf_terminate_myself();
    }

    /*
    if (thread->iob_array.count > 1) {
        logInfo("%s batch_write count: %d, success: %d, bytes: %d",
                thread->path_info->ctx->module_name,
                thread->iob_array.count, thread->iob_array.success,
                thread->iovec_bytes);
    }
    */

    thread->iovec_bytes = 0;
    thread->iovec_array.count = 0;
    thread->iob_array.count = 0;
    return result;
}

#define IOB_IS_SUCCESSIVE(last, current)  \
    ((current->space.id_info.id == last->space.id_info.id) && \
     (last->space.offset + last->space.size == current->space.offset))

static int align_write_buffer(TrunkWriteThreadContext *thread,
        TrunkWriteIOBuffer *iob, const int padding_bytes)
{
    char trunk_filename[PATH_MAX];
    char *start;
    int fd;
    int read_bytes;
    int result;

    if (thread->direct_io.file.trunk_id == iob->space.id_info.id &&
            thread->direct_io.file.last_offset == iob->space.offset)
    {
        start = thread->direct_io.buffer.last - thread->path_info->block_size;
        if (start != thread->direct_io.buffer.buff) {
            memcpy(thread->direct_io.buffer.buff, start, padding_bytes);
        }
        return 0;
    }

    dio_get_trunk_filename(&iob->space, trunk_filename,
            sizeof(trunk_filename));
    fd = open(trunk_filename, thread->direct_io.file.read_flags, 0644);
    if (fd < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, thread->path_info->ctx->module_name,
                trunk_filename, result, STRERROR(result));
        return result;
    }

    /*
    logInfo("trunk id: %"PRId64", offset: %u, read bytes: %d",
            iob->space.id_info.id, thread->direct_io.file.
            first_offset, thread->path_info->block_size);
            */

    read_bytes = pread(fd, thread->direct_io.buffer.buff, thread->
            path_info->block_size, thread->direct_io.file.first_offset);
    if (read_bytes == thread->path_info->block_size) {
        result = 0;
    } else {
        result = errno != 0 ? errno : EIO;
        logError("file: "__FILE__", line: %d, %s "
                "trunk file: %s, offset: %u, read %d bytes fail, errno: %d, "
                "error info: %s", __LINE__, thread->path_info->ctx->
                module_name, trunk_filename, thread->direct_io.file.
                first_offset, thread->path_info->block_size,
                result, STRERROR(result));
    }

    close(fd);
    return result;
}

static void deal_write_request(TrunkWriteThreadContext *thread,
        TrunkWriteIOBuffer *iob)
{
    TrunkWriteIOBuffer *last;
    struct iovec *current;
    struct iovec *src;
    struct iovec *end;
    struct iovec *dest;
    int total;
    int padding;
    int padding_bytes;
    int inc_count;

    if (thread->iob_array.count > 0) {
        last = thread->iob_array.iobs[thread->iob_array.count - 1];
        if (!(IOB_IS_SUCCESSIVE(last, iob) &&
                    (thread->iob_array.count < thread->iob_array.alloc) &&
                    (thread->iovec_array.count < IOV_MAX) &&
                    (thread->iovec_bytes + iob->space.size <=
                     thread->write_bytes_max)))
        {
            batch_write(thread);
        }
    }

    if (thread->path_info->write_direct_io) {
        if (thread->iob_array.count > 0) {
            if (thread->direct_io.buffer.last + MEM_ALIGN_CEIL_BY_MASK(iob->
                        space.size, thread->path_info->block_align_mask) >
                    thread->direct_io.buffer.end)
            {
                batch_write(thread);
            }
        }

        if (thread->iob_array.count == 0) {
            padding_bytes = (iob->space.offset & thread->
                    path_info->block_align_mask);
            if (padding_bytes == 0) {
                thread->direct_io.file.first_offset = iob->space.offset;
                thread->direct_io.buffer.last = thread->direct_io.buffer.buff;
            } else {
                thread->direct_io.file.first_offset =
                    iob->space.offset - padding_bytes;
                if (align_write_buffer(thread, iob, padding_bytes) != 0) {
                    sf_terminate_myself();
                    return;
                }
                thread->direct_io.buffer.last = thread->
                    direct_io.buffer.buff + padding_bytes;
            }

            thread->direct_io.file.trunk_id = iob->space.id_info.id;
        }

        if (iob->op_type == DA_IO_TYPE_WRITE_SLICE_BY_BUFF) {
            memcpy(thread->direct_io.buffer.last, iob->buff, iob->space.size);
            thread->direct_io.buffer.last += iob->space.size;
            thread->iovec_array.count++;
        } else {
            total = 0;
            end = iob->iovec_array.iovs + iob->iovec_array.count;
            for (src=iob->iovec_array.iovs; src<end; src++) {
                memcpy(thread->direct_io.buffer.last,
                        src->iov_base, src->iov_len);
                thread->direct_io.buffer.last += src->iov_len;
                total += src->iov_len;
            }
            padding = iob->space.size - total;
            if (padding > 0) {
                thread->direct_io.buffer.last += padding;
            }
            thread->iovec_array.count += iob->iovec_array.count;
        }

        thread->direct_io.file.last_offset =
            iob->space.offset + iob->space.size;
    } else {
        inc_count = (iob->op_type == DA_IO_TYPE_WRITE_SLICE_BY_BUFF ?
                1 : iob->iovec_array.count);
        if (fc_check_realloc_iovec_array(&thread->iovec_array,
                    thread->iovec_array.count + inc_count) != 0)
        {
            return;
        }

        if (iob->op_type == DA_IO_TYPE_WRITE_SLICE_BY_BUFF) {
            current = thread->iovec_array.iovs +
                thread->iovec_array.count++;
            current->iov_base = iob->buff;
            current->iov_len = iob->space.size;
        } else if (iob->iovec_array.count == 1) {  //fast path
            current = thread->iovec_array.iovs +
                thread->iovec_array.count++;
            current->iov_base = iob->iovec_array.iovs[0].iov_base;
            current->iov_len = iob->space.size;
        } else {
            total = 0;
            dest = thread->iovec_array.iovs + thread->iovec_array.count;
            end = iob->iovec_array.iovs + iob->iovec_array.count;
            for (src=iob->iovec_array.iovs; src<end; src++) {
                *dest++ = *src;
                total += src->iov_len;
            }

            padding = iob->space.size - total;
            if (padding > 0) {
                (dest - 1)->iov_len += padding;
            }

            thread->iovec_array.count += iob->iovec_array.count;
        }
    }

    thread->iob_array.iobs[thread->iob_array.count++] = iob;
    thread->iovec_bytes += iob->space.size;
}

static inline void batch_free_mblock_chain(TrunkWriteThreadContext *thread)
{
    if (thread->batch_free_chain.head != NULL) {
        thread->batch_free_chain.tail->next = NULL;
        fast_mblock_batch_free(&thread->mblock, &thread->batch_free_chain);
        thread->batch_free_chain.head = NULL;
        thread->batch_free_chain.tail = NULL;
    }
}

static void deal_requests(TrunkWriteThreadContext *thread,
        struct fc_list_head *head)
{
    TrunkWriteIOBuffer *iob;
    int result;

    fc_list_for_each_entry(iob, head, dlink) {
        switch (iob->op_type) {
            case DA_IO_TYPE_QUIT:
                add_to_batch_free_chain(thread, iob);
                return;
            case DA_IO_TYPE_CREATE_TRUNK:
            case DA_IO_TYPE_DELETE_TRUNK:
                if (iob->op_type == DA_IO_TYPE_CREATE_TRUNK) {
                    result = do_create_trunk(thread, iob);
                } else {
                    result = do_delete_trunk(thread, iob);
                }

                if (iob->notify.func != NULL) {
                    iob->notify.func(iob, result);
                }

                if (result != 0) {
                    sf_terminate_myself();
                    return;
                }

                add_to_batch_free_chain(thread, iob);
                break;
            case DA_IO_TYPE_WRITE_SLICE_BY_BUFF:
            case DA_IO_TYPE_WRITE_SLICE_BY_IOVEC:
                deal_write_request(thread, iob);
                break;
            default:
                logError("file: "__FILE__", line: %d, %s "
                        "invalid op_type: %d", __LINE__, thread->
                        path_info->ctx->module_name, iob->op_type);
                sf_terminate_myself();
                return;
        }

        if (!SF_G_CONTINUE_FLAG) {
            break;
        }
    }
}

static void *da_trunk_write_thread_func(void *arg)
{
    TrunkWriteThreadContext *thread;
    struct fc_list_head head;

    thread = (TrunkWriteThreadContext *)arg;
#ifdef OS_LINUX
    {
        int len;
        const char *module_name;
        char thread_name[16];

        if (thread->path_info->ctx->module_name[0] == '[') {
            module_name = thread->path_info->ctx->module_name + 1;
        } else {
            module_name = thread->path_info->ctx->module_name;
        }
        len = snprintf(thread_name, sizeof(thread_name),
                "%.*s-dio-p%d-w", 3, module_name,
                thread->indexes.path);
        if (thread->indexes.thread >= 0) {
            snprintf(thread_name + len, sizeof(thread_name) - len,
                    "[%d]", thread->indexes.thread);
        }
        prctl(PR_SET_NAME, thread_name);
    }
#endif

    FC_ATOMIC_INC(thread->ctx->trunk_write_ctx->running_threads);
    while (SF_G_CONTINUE_FLAG) {
        sorted_queue_pop_to_chain_ex(&thread->queue, &thread->less_than,
                &head, thread->iob_array.count == 0);
        if (fc_list_empty(&head)) {
            if (thread->iob_array.count > 0) {
                batch_write(thread);
                batch_free_mblock_chain(thread);
            }
            fc_sleep_ms(1);
            continue;
        }

        deal_requests(thread, &head);
        batch_free_mblock_chain(thread);
    }

    if (thread->iob_array.count > 0) {
        batch_write(thread);
    }
    clear_write_fd(thread);
    FC_ATOMIC_DEC(thread->ctx->trunk_write_ctx->running_threads);

    return NULL;
}

static void write_io_notify_callback(struct da_trunk_write_io_buffer
        *buffer, const int result)
{
    SFSynchronizeContext *sctx;

    sctx = buffer->notify.arg1;
    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    sctx->result = result;
    pthread_cond_signal(&sctx->lcp.cond);
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);
}

int da_trunk_write_thread_by_buff_synchronize(DAContext *ctx,
        DATrunkSpaceWithVersion *space_info, char *buff,
        SFSynchronizeContext *sctx)
{
    int result;

    sctx->result = INT16_MIN;
    if ((result=da_trunk_write_thread_push_slice_by_buff(ctx,
                    space_info->version, &space_info->ts.space, buff,
                    write_io_notify_callback, sctx, NULL)) != 0)
    {
        return result;
    }

    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    while (sctx->result == INT16_MIN) {
        pthread_cond_wait(&sctx->lcp.cond,
                &sctx->lcp.lock);
    }
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);

    return sctx->result;
}

int da_trunk_write_thread_by_iovec_synchronize(DAContext *ctx,
        DATrunkSpaceWithVersion *space_info, iovec_array_t *iovec_array,
        SFSynchronizeContext *sctx)
{
    int result;

    sctx->result = INT16_MIN;
    if ((result=da_trunk_write_thread_push_slice_by_iovec(ctx, space_info->
                    version, &space_info->ts.space, iovec_array,
                    write_io_notify_callback, sctx, NULL)) != 0)
    {
        return result;
    }

    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    while (sctx->result == INT16_MIN) {
        pthread_cond_wait(&sctx->lcp.cond,
                &sctx->lcp.lock);
    }
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);

    return sctx->result;
}
