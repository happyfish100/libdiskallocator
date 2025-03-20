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
#include <sys/param.h>
#include <sys/mount.h>
#include "fastcommon/common_define.h"
#include "fastcommon/shared_func.h"
#include "fastcommon/logger.h"
#include "fastcommon/fast_mblock.h"
#include "fastcommon/uniq_skiplist.h"
#include "sf/sf_global.h"
#include "sf/sf_func.h"
#include "../global.h"
#include "../trunk/trunk_hashtable.h"
#include "trunk_fd_cache.h"
#ifdef OS_LINUX
#include "read_buffer_pool.h"
#endif
#include "trunk_read_thread.h"

typedef struct da_trunk_read_thread_context {
    const DAStoragePathInfo *path_info;
    struct {
        short path;
        short thread;
    } indexes;
    struct fc_queue queue;
    struct fast_mblock_man mblock;
    DATrunkFDCacheContext fd_cache;

#ifdef OS_LINUX
    struct {
        int count;
        int alloc;
        struct iocb **pp;
    } iocbs;

    struct {
        int doing_count;  //in progress count
        int max_event;
        struct io_event *events;
        io_context_t ctx;
    } aio;

#endif

} TrunkReadThreadContext;

typedef struct da_trunk_read_thread_context_array {
    int count;
    TrunkReadThreadContext *contexts;
} TrunkReadThreadContextArray;

typedef struct trunk_read_path_context {
    TrunkReadThreadContextArray reads;
} TrunkReadPathContext;

typedef struct trunk_read_path_contexts_array {
    int count;
    TrunkReadPathContext *paths;
} TrunkReadPathContextArray;

typedef struct da_trunk_read_context {
    TrunkReadPathContextArray path_ctx_array;
} TrunkReadContext;

static void *da_trunk_read_thread_func(void *arg);

static inline int init_op_ctx(DASliceOpContext *op_ctx)
{
    const int alloc_size = 64 * 1024;

    op_ctx->storage = NULL;

#ifdef OS_LINUX
    op_ctx->rb.aio_buffer = NULL;
#endif

    op_ctx->rb.buffer.ptr = &op_ctx->rb.buffer.holder;
    return fc_init_buffer(op_ctx->rb.buffer.ptr, alloc_size);
}

int da_init_read_context(DASynchronizedReadContext *ctx)
{
    int result;

    if ((result=init_op_ctx(&ctx->op_ctx)) != 0) {
        return result;
    }

    if ((result=sf_synchronize_ctx_init(&ctx->sctx)) != 0) {
        return result;
    }

    return 0;
}

void da_destroy_read_context(DAContext *ctx, DASynchronizedReadContext *rctx)
{
#ifdef OS_LINUX
    if (rctx->op_ctx.rb.aio_buffer != NULL) {
        da_read_buffer_pool_free(ctx, rctx->op_ctx.rb.aio_buffer);
        rctx->op_ctx.rb.aio_buffer = NULL;
    }
#endif

    fc_free_buffer(&rctx->op_ctx.rb.buffer.holder);
    sf_synchronize_ctx_destroy(&rctx->sctx);
}

static int alloc_path_contexts(DAContext *ctx)
{
    int count;
    int bytes;

    count = ctx->storage.cfg.max_store_path_index + 1;
    bytes = sizeof(TrunkReadContext) + sizeof(TrunkReadPathContext) * count;
    ctx->trunk_read_ctx = fc_malloc(bytes);
    if (ctx->trunk_read_ctx == NULL) {
        return ENOMEM;
    }
    memset(ctx->trunk_read_ctx, 0, bytes);
    ctx->trunk_read_ctx->path_ctx_array.count = count;
    ctx->trunk_read_ctx->path_ctx_array.paths = (TrunkReadPathContext *)
        (ctx->trunk_read_ctx + 1);
    return 0;
}

static TrunkReadThreadContext *alloc_thread_contexts(const int count)
{
    TrunkReadThreadContext *contexts;
    int bytes;

    bytes = sizeof(TrunkReadThreadContext) * count;
    contexts = (TrunkReadThreadContext *)fc_malloc(bytes);
    if (contexts == NULL) {
        return NULL;
    }
    memset(contexts, 0, bytes);
    return contexts;
}

static int init_thread_context(DAContext *ctx,
        TrunkReadThreadContext *thread,
        const DAStoragePathInfo *path_info)
{
    int result;
    pthread_t tid;

    if ((result=fast_mblock_init_ex1(&thread->mblock, "trunk_read_buffer",
                    sizeof(DATrunkReadIOBuffer), 1024, 0, NULL,
                    NULL, true)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&thread->queue, (long)
                    (&((DATrunkReadIOBuffer *)NULL)->next))) != 0)
    {
        return result;
    }


    if ((result=da_trunk_fd_cache_init(&thread->fd_cache, ctx->storage.cfg.
                    fd_cache_capacity_per_read_thread)) != 0)
    {
        return result;
    }

#ifdef OS_LINUX
    if (path_info->read_direct_io) {
        thread->iocbs.alloc = path_info->read_io_depth;
        thread->iocbs.pp = (struct iocb **)fc_malloc(sizeof(
                    struct iocb *) * thread->iocbs.alloc);
        if (thread->iocbs.pp == NULL) {
            return ENOMEM;
        }

        thread->aio.max_event = path_info->read_io_depth;
        thread->aio.events = (struct io_event *)fc_malloc(sizeof(
                    struct io_event) * thread->aio.max_event);
        if (thread->aio.events == NULL) {
            return ENOMEM;
        }

        thread->aio.ctx = 0;
        if (io_setup(thread->aio.max_event, &thread->aio.ctx) != 0) {
            result = errno != 0 ? errno : ENOMEM;
            logError("file: "__FILE__", line: %d, %s "
                    "io_setup fail, errno: %d, error info: %s",
                    __LINE__, ctx->module_name, result, STRERROR(result));
            return result;
        }
        thread->aio.doing_count = 0;
    }

#endif

    return fc_create_thread(&tid, da_trunk_read_thread_func,
            thread, SF_G_THREAD_STACK_SIZE);
}

static int init_thread_contexts(DAContext *ctx,
        TrunkReadThreadContextArray *ctx_array,
        const DAStoragePathInfo *path_info)
{
    int result;
    TrunkReadThreadContext *thread;
    TrunkReadThreadContext *end;

    end = ctx_array->contexts + ctx_array->count;
    for (thread=ctx_array->contexts; thread<end; thread++) {
        thread->path_info = path_info;
        thread->indexes.path = path_info->store.index;
        if (ctx_array->count == 1) {
            thread->indexes.thread = -1;
        } else {
            thread->indexes.thread = thread - ctx_array->contexts;
        }
        if ((result=init_thread_context(ctx, thread, path_info)) != 0) {
            return result;
        }
    }

    return 0;
}

static int init_path_contexts(DAContext *ctx, DAStoragePathArray *parray)
{
    DAStoragePathInfo *p;
    DAStoragePathInfo *end;
    TrunkReadThreadContext *thread_ctxs;
    TrunkReadPathContext *path_ctx;
    int result;

    end = parray->paths + parray->count;
    for (p=parray->paths; p<end; p++) {
        path_ctx = ctx->trunk_read_ctx->path_ctx_array.paths + p->store.index;
        if ((thread_ctxs=alloc_thread_contexts(
                        p->read_thread_count)) == NULL)
        {
            return ENOMEM;
        }

        path_ctx->reads.contexts = thread_ctxs;
        path_ctx->reads.count = p->read_thread_count;
        if ((result=init_thread_contexts(ctx, &path_ctx->reads, p)) != 0) {
            return result;
        }
    }

    return 0;
}

#ifdef OS_LINUX
static int rbpool_init_start(DAContext *ctx)
{
    SFMemoryWatermark memory_watermark;
    DAStoragePathInfo **pp;
    DAStoragePathInfo **end;
    int path_count;
    int result;

    path_count = da_storage_config_path_count(&ctx->storage.cfg);
    memory_watermark.low = ctx->storage.cfg.aio_read_buffer.
        memory_watermark_low.value / path_count;
    memory_watermark.high = ctx->storage.cfg.aio_read_buffer.
        memory_watermark_high.value / path_count;
    if ((result=da_read_buffer_pool_init(ctx, ctx->storage.cfg.
                    paths_by_index.count, &memory_watermark)) != 0)
    {
        return result;
    }

    end = ctx->storage.cfg.paths_by_index.paths +
        ctx->storage.cfg.paths_by_index.count;
    for (pp=ctx->storage.cfg.paths_by_index.paths; pp<end; pp++) {
        if (*pp != NULL) {
            if ((result=da_read_buffer_pool_create(ctx, (*pp)->store.index,
                            (*pp)->block_size)) != 0)
            {
                return result;
            }
        }
    }

    return da_read_buffer_pool_start(ctx, ctx->storage.cfg.aio_read_buffer.
            max_idle_time, ctx->storage.cfg.aio_read_buffer.reclaim_interval);
}
#endif

int da_trunk_read_thread_init(DAContext *ctx)
{
    int result;

#ifdef OS_LINUX
    if (ctx->storage.read_direct_io_paths > 0) {
        if ((result=rbpool_init_start(ctx)) != 0) {
            return result;
        }
    }
#endif

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
       logInfo("%s ctx->trunk_read_ctx->path_ctx_array.count: %d",
               ctx->module_name, ctx->trunk_read_ctx->path_ctx_array.count);
     */
    return 0;
}

void da_trunk_read_thread_terminate(DAContext *ctx)
{
}

int da_trunk_read_thread_push(DAContext *ctx, const DATrunkSpaceInfo *space,
        const int read_bytes, DATrunkReadBuffer *rb,
        da_trunk_read_io_notify_func notify_func, void *notify_arg)
{
    TrunkReadPathContext *path_ctx;
    TrunkReadThreadContext *thread_ctx;
    DATrunkReadIOBuffer *iob;

    path_ctx = ctx->trunk_read_ctx->path_ctx_array.paths +
        space->store->index;
    thread_ctx = path_ctx->reads.contexts + space->
        id_info.id % path_ctx->reads.count;
    iob = (DATrunkReadIOBuffer *)fast_mblock_alloc_object(&thread_ctx->mblock);
    if (iob == NULL) {
        return ENOMEM;
    }

    iob->space = *space;
    iob->read_bytes = read_bytes;
    iob->rb = rb;
    iob->notify.func = notify_func;
    iob->notify.arg = notify_arg;

    fc_queue_push(&thread_ctx->queue, iob);
    return 0;
}

static int get_read_fd(TrunkReadThreadContext *thread,
        DATrunkSpaceInfo *space, int *fd)
{
    char trunk_filename[PATH_MAX];
    int result;

    if ((*fd=da_trunk_fd_cache_get(&thread->fd_cache,
                    space->id_info.id)) >= 0)
    {
        return 0;
    }

    dio_get_trunk_filename(space, trunk_filename, sizeof(trunk_filename));
#ifdef OS_LINUX
    if (thread->path_info->read_direct_io) {
        *fd = open(trunk_filename, O_RDONLY | O_DIRECT | O_CLOEXEC);
    } else {
        *fd = open(trunk_filename, O_RDONLY | O_CLOEXEC);
    }
#else
    *fd = open(trunk_filename, O_RDONLY | O_CLOEXEC);
#endif
    if (*fd < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, %s "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, thread->path_info->ctx->module_name,
                trunk_filename, result, STRERROR(result));
        return result;
    }

    da_trunk_fd_cache_add(&thread->fd_cache, space->id_info.id, *fd);
    return 0;
}

#ifdef OS_LINUX

static inline int prepare_read_slice(TrunkReadThreadContext *thread,
        DATrunkReadIOBuffer *iob)
{
    const bool need_align = false;
    int64_t new_offset;
    int offset;
    int read_bytes;
    int result;
    int fd;
    bool new_alloced;

    new_offset = MEM_ALIGN_FLOOR_BY_MASK(iob->space.offset,
            thread->path_info->block_align_mask);
    read_bytes = MEM_ALIGN_CEIL_BY_MASK(iob->read_bytes,
            thread->path_info->block_align_mask);
    offset = iob->space.offset - new_offset;
    if (offset > 0) {
        if (new_offset + read_bytes < iob->space.offset +
                iob->read_bytes)
        {
            read_bytes += thread->path_info->block_size;
        }
    }

    if (iob->rb->aio_buffer != NULL && iob->rb->
            aio_buffer->size < read_bytes)
    {
        logWarning("file: "__FILE__", line: %d, %s "
                "buffer size %d is too small, required size: %d",
                __LINE__, thread->path_info->ctx->module_name,
                iob->rb->aio_buffer->size, read_bytes);

        da_read_buffer_pool_free(thread->path_info->ctx, iob->rb->aio_buffer);
        iob->rb->aio_buffer = NULL;
    }

    if (iob->rb->aio_buffer == NULL) {
        iob->rb->aio_buffer = da_read_buffer_pool_alloc(thread->path_info->
                ctx, thread->indexes.path, read_bytes, need_align);
        if (iob->rb->aio_buffer == NULL) {
            return ENOMEM;
        }
        new_alloced = true;
    } else {
        new_alloced = false;
    }

    iob->rb->aio_buffer->offset = offset;
    iob->rb->aio_buffer->length = iob->read_bytes;
    iob->rb->aio_buffer->read_bytes = read_bytes;

    /*
    logInfo("%s space.offset: %"PRId64", new_offset: %"PRId64", "
            "offset: %d, read_bytes: %d, size: %d", thread->path_info->
            ctx->module_name, iob->space.offset, new_offset, offset,
            read_bytes, iob->rb->aio_buffer->size);
            */

    if ((result=get_read_fd(thread, &iob->space, &fd)) != 0) {
        if (new_alloced) {
            da_read_buffer_pool_free(thread->path_info->ctx, iob->rb->aio_buffer);
            iob->rb->aio_buffer = NULL;
        }
        return result;
    }

    io_prep_pread(&iob->iocb, fd, iob->rb->aio_buffer->buff,
            iob->rb->aio_buffer->read_bytes, new_offset);
    iob->iocb.data = iob;
    thread->iocbs.pp[thread->iocbs.count++] = &iob->iocb;
    return 0;
}

static int consume_queue(TrunkReadThreadContext *thread)
{
    struct fc_queue_info qinfo;
    DATrunkReadIOBuffer *iob;
    int target_count;
    int count;
    int remain;
    int n;
    int result;

    fc_queue_pop_to_queue_ex(&thread->queue, &qinfo, thread->aio.doing_count == 0);
    if (qinfo.head == NULL) {
        return 0;
    }

    target_count = thread->aio.max_event - thread->aio.doing_count;
    thread->iocbs.count = 0;
    iob = (DATrunkReadIOBuffer *)qinfo.head;
    do {
        if ((result=prepare_read_slice(thread, iob)) != 0) {
            return result;
        }

        iob = iob->next;
    } while (iob != NULL && thread->iocbs.count < target_count);

    count = 0;
    while ((remain=thread->iocbs.count - count) > 0) {
        if ((n=io_submit(thread->aio.ctx, remain,
                        thread->iocbs.pp + count)) <= 0)
        {
            result = errno != 0 ? errno : ENOMEM;
            if (result == EINTR) {
                continue;
            }

            logError("file: "__FILE__", line: %d, %s "
                    "io_submiti return %d != %d, "
                    "errno: %d, error info: %s", __LINE__,
                    thread->path_info->ctx->module_name, count,
                    thread->iocbs.count, result, STRERROR(result));
            return result;
        }

        count += n;
    }

    thread->aio.doing_count += thread->iocbs.count;
    if (iob != NULL) {
        qinfo.head = iob;
        fc_queue_push_queue_to_head_silence(&thread->queue, &qinfo);
    }
    return 0;
}

static int process_aio(TrunkReadThreadContext *thread)
{
    struct timespec tms;
    DATrunkReadIOBuffer *iob;
    struct io_event *event;
    struct io_event *end;
    char trunk_filename[PATH_MAX];
    bool full;
    int count;
    int result;

    full = thread->aio.doing_count >= thread->aio.max_event;
    while (1) {
        if (full) {
            tms.tv_sec = 1;
            tms.tv_nsec = 0;
        } else {
            tms.tv_sec = 0;
            if (thread->aio.doing_count < 10) {
                tms.tv_nsec = thread->aio.doing_count * 1000 * 1000;
            } else {
                tms.tv_nsec = 10 * 1000 * 1000;
            }
        }
        count = io_getevents(thread->aio.ctx, 1, thread->aio.
                max_event, thread->aio.events, &tms);
        if (count > 0) {
            break;
        } else if (count == 0) {  //timeout
            if (full) {
                continue;
            } else {
                return 0;
            }
        } else {
            result = errno != 0 ? errno : ENOMEM;
            if (result == EINTR) {
                if (full) {
                    continue;
                } else {
                    return 0;
                }
            }

            logCrit("file: "__FILE__", line: %d, %s "
                    "io_getevents fail, errno: %d, error info: %s",
                    __LINE__, thread->path_info->ctx->module_name,
                    result, STRERROR(result));
            return result;
        }
    }

    end = thread->aio.events + count;
    for (event=thread->aio.events; event<end; event++) {
        iob = (DATrunkReadIOBuffer *)event->data;
        if (event->res == iob->rb->aio_buffer->read_bytes) {
            result = 0;
        } else {
            da_trunk_fd_cache_delete(&thread->fd_cache,
                    iob->space.id_info.id);

            if ((int)event->res < 0) {
                result = -1 * event->res;
            } else {
                result = EBUSY;
            }
            dio_get_trunk_filename(&iob->space, trunk_filename,
                    sizeof(trunk_filename));
            logError("file: "__FILE__", line: %d, %s "
                    "read trunk file: %s fail, offset: %u, "
                    "expect length: %d, read return: %d, errno: %d, "
                    "error info: %s", __LINE__, thread->path_info->ctx->
                    module_name, trunk_filename, iob->space.offset - iob->
                    rb->aio_buffer->offset, iob->rb->aio_buffer->read_bytes,
                    (int)event->res, result, STRERROR(result));
        }

        iob->notify.func(iob, result);
        fast_mblock_free_object(&thread->mblock, iob);
    }
    thread->aio.doing_count -= count;

    return 0;
}

static inline int process(TrunkReadThreadContext *thread)
{
    int result;

    if ((result=consume_queue(thread)) != 0) {
        return result;
    }

    if (thread->aio.doing_count <= 0) {
        return 0;
    }

    return process_aio(thread);
}

#endif

static int do_read_slice(TrunkReadThreadContext *thread, DATrunkReadIOBuffer *iob)
{
    int fd;
    int remain;
    int bytes;
    int result;

    if ((result=get_read_fd(thread, &iob->space, &fd)) != 0) {
        return result;
    }

    iob->rb->buffer.ptr->length = 0;
    remain = iob->read_bytes;
    while (remain > 0) {
        bytes = pread(fd, iob->rb->buffer.ptr->buff + iob->rb->
                buffer.ptr->length, remain, iob->space.offset +
                iob->rb->buffer.ptr->length);
        if (bytes <= 0) {
            char trunk_filename[PATH_MAX];

            result = errno != 0 ? errno : EIO;
            if (result == EINTR) {
                continue;
            }

            da_trunk_fd_cache_delete(&thread->fd_cache,
                    iob->space.id_info.id);

            dio_get_trunk_filename(&iob->space, trunk_filename,
                    sizeof(trunk_filename));
            logError("file: "__FILE__", line: %d, %s "
                    "read trunk file: %s fail, offset: %u, "
                    "errno: %d, error info: %s", __LINE__, thread->path_info->
                    ctx->module_name, trunk_filename, iob->space.offset +
                    iob->rb->buffer.ptr->length, result, STRERROR(result));
            return result;
        }

        iob->rb->buffer.ptr->length += bytes;
        remain -= bytes;
    }

    return 0;
}

static void normal_read_loop(TrunkReadThreadContext *thread)
{
    int result;
    DATrunkReadIOBuffer *iob;

    while (SF_G_CONTINUE_FLAG) {
        if ((iob=(DATrunkReadIOBuffer *)fc_queue_pop(&thread->queue)) == NULL) {
            continue;
        }

        if ((result=do_read_slice(thread, iob)) != 0) {
            logError("file: "__FILE__", line: %d, %s "
                    "slice read fail, result: %d", __LINE__,
                    thread->path_info->ctx->module_name, result);
        }

        if (iob->notify.func != NULL) {
            iob->notify.func(iob, result);
        }
        fast_mblock_free_object(&thread->mblock, iob);
    }
}

static void *da_trunk_read_thread_func(void *arg)
{
    TrunkReadThreadContext *thread;
#ifdef OS_LINUX
    int len;
    const char *module_name;
    char thread_name[16];
#endif

    thread = (TrunkReadThreadContext *)arg;

#ifdef OS_LINUX
    if (thread->path_info->ctx->module_name[0] == '[') {
        module_name = thread->path_info->ctx->module_name + 1;
    } else {
        module_name = thread->path_info->ctx->module_name;
    }
    len = snprintf(thread_name, sizeof(thread_name),
            "%.*s-dio-p%d-r", 3, module_name,
            thread->indexes.path);
    if (thread->indexes.thread >= 0) {
        snprintf(thread_name + len, sizeof(thread_name) - len,
                "[%d]", thread->indexes.thread);
    }
    prctl(PR_SET_NAME, thread_name);

    if (thread->path_info->read_direct_io) {
        while (SF_G_CONTINUE_FLAG) {
            if (process(thread) != 0) {
                sf_terminate_myself();
                break;
            }
        }
    } else {
        normal_read_loop(thread);
    }
#else
    normal_read_loop(thread);
#endif

    return NULL;
}

static void slice_read_done(struct da_trunk_read_io_buffer
        *record, const int result)
{
    SFSynchronizeContext *sctx;

    sctx = (SFSynchronizeContext *)record->notify.arg;
    PTHREAD_MUTEX_LOCK(&sctx->lcp.lock);
    sctx->result = result;
    pthread_cond_signal(&sctx->lcp.cond);
    PTHREAD_MUTEX_UNLOCK(&sctx->lcp.lock);
}

static int check_alloc_buffer(DASliceOpContext *op_ctx,
        const DAStoragePathInfo *path_info, BufferInfo *buffer)
{
#ifdef OS_LINUX
    const bool need_align = false;
    int aligned_size;

    if (path_info->read_direct_io) {
        op_ctx->rb.type = da_buffer_type_aio;
        aligned_size = op_ctx->storage->size + path_info->block_size * 2;
        if (op_ctx->rb.aio_buffer != NULL && (op_ctx->rb.aio_buffer->
                    size < aligned_size || op_ctx->rb.aio_buffer->
                    size % path_info->block_size != 0))
        {
            DAAlignedReadBuffer *new_buffer;

            new_buffer = da_read_buffer_pool_alloc(path_info->ctx,
                    path_info->store.index, aligned_size, need_align);
            if (new_buffer == NULL) {
                return ENOMEM;
            }

            da_read_buffer_pool_free(path_info->ctx, op_ctx->rb.aio_buffer);
            op_ctx->rb.aio_buffer = new_buffer;
        }

        return 0;
    } else {
        op_ctx->rb.type = da_buffer_type_direct;
    }
#endif

    if (buffer == NULL) {
        op_ctx->rb.buffer.ptr = &op_ctx->rb.buffer.holder;
        if (op_ctx->rb.buffer.ptr->alloc_size < op_ctx->storage->size) {
            char *buff;
            int buffer_size;

            buffer_size = op_ctx->rb.buffer.ptr->alloc_size * 2;
            while (buffer_size < op_ctx->storage->size) {
                buffer_size *= 2;
            }
            buff = (char *)fc_malloc(buffer_size);
            if (buff == NULL) {
                return ENOMEM;
            }

            free(op_ctx->rb.buffer.ptr->buff);
            op_ctx->rb.buffer.ptr->buff = buff;
            op_ctx->rb.buffer.ptr->alloc_size = buffer_size;
        }
    } else {
        op_ctx->rb.buffer.ptr = buffer;
    }

    return 0;
}

int da_slice_read_ex(DAContext *ctx, DASynchronizedReadContext *rctx,
        BufferInfo *buffer)
{
    int result;
    DATrunkSpaceInfo space;
    DATrunkFileInfo *trunk;

    if ((trunk=da_trunk_hashtable_get(&ctx->trunk_htable_ctx,
                    rctx->op_ctx.storage->trunk_id)) == NULL)
    {
        return ENOENT;
    }

    if ((result=check_alloc_buffer(&rctx->op_ctx, trunk->
                    allocator->path_info, buffer)) != 0)
    {
        return result;
    }

    rctx->sctx.result = INT16_MIN;
    space.store = &trunk->allocator->path_info->store;
    space.id_info = trunk->id_info;
    space.offset = rctx->op_ctx.storage->offset;
    space.size = rctx->op_ctx.storage->size;
    if ((result=da_trunk_read_thread_push(ctx, &space, rctx->
                    op_ctx.storage->length, &rctx->op_ctx.rb,
                    slice_read_done, &rctx->sctx)) != 0)
    {
        return result;
    }

    PTHREAD_MUTEX_LOCK(&rctx->sctx.lcp.lock);
    while (rctx->sctx.result == INT16_MIN && SF_G_CONTINUE_FLAG) {
        pthread_cond_wait(&rctx->sctx.lcp.cond,
                &rctx->sctx.lcp.lock);
    }
    result = rctx->sctx.result == INT16_MIN ? EINTR : rctx->sctx.result;
    PTHREAD_MUTEX_UNLOCK(&rctx->sctx.lcp.lock);

#ifdef OS_LINUX
    if (buffer != NULL && rctx->op_ctx.rb.type == da_buffer_type_aio) {
        buffer->length = DA_OP_CTX_AIO_BUFFER_LEN(rctx->op_ctx);
        memcpy(buffer->buff, DA_OP_CTX_AIO_BUFFER_PTR(
                    rctx->op_ctx), buffer->length);
    }
#endif

    return result;
}
