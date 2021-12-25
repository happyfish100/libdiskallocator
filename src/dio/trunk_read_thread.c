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

typedef struct trunk_read_thread_context {
    struct {
        short path;
        short thread;
    } indexes;
    int block_size;
    struct fc_queue queue;
    struct fast_mblock_man mblock;
    TrunkFDCacheContext fd_cache;

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

typedef struct trunk_read_thread_context_array {
    int count;
    TrunkReadThreadContext *contexts;
} TrunkReadThreadContextArray;

typedef struct trunk_io_path_context {
    TrunkReadThreadContextArray reads;
} TrunkReadPathContext;

typedef struct trunk_io_path_contexts_array {
    int count;
    TrunkReadPathContext *paths;
} TrunkReadPathContextArray;

typedef struct trunk_io_context {
    TrunkReadPathContextArray path_ctx_array;
} TrunkReadContext;

static TrunkReadContext trunk_io_ctx = {{0, NULL}};

static void *trunk_read_thread_func(void *arg);

int da_init_read_context(DASynchronizedReadContext *ctx)
{
    int result;

    if ((result=da_init_op_ctx(&ctx->op_ctx)) != 0) {
        return result;
    }

    if ((result=sf_synchronize_ctx_init(&ctx->sctx)) != 0) {
        return result;
    }

    return 0;
}

static int alloc_path_contexts()
{
    int bytes;

    trunk_io_ctx.path_ctx_array.count = DA_STORE_CFG.max_store_path_index + 1;
    bytes = sizeof(TrunkReadPathContext) * trunk_io_ctx.path_ctx_array.count;
    trunk_io_ctx.path_ctx_array.paths = (TrunkReadPathContext *)fc_malloc(bytes);
    if (trunk_io_ctx.path_ctx_array.paths == NULL) {
        return ENOMEM;
    }
    memset(trunk_io_ctx.path_ctx_array.paths, 0, bytes);
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

static int init_thread_context(TrunkReadThreadContext *ctx,
        const DAStoragePathInfo *path_info)
{
    int result;
    pthread_t tid;

    if ((result=fast_mblock_init_ex1(&ctx->mblock, "trunk_read_buffer",
                    sizeof(DATrunkReadIOBuffer), 1024, 0, NULL,
                    NULL, true)) != 0)
    {
        return result;
    }

    if ((result=fc_queue_init(&ctx->queue, (long)
                    (&((DATrunkReadIOBuffer *)NULL)->next))) != 0)
    {
        return result;
    }


    if ((result=trunk_fd_cache_init(&ctx->fd_cache, DA_STORE_CFG.
                    fd_cache_capacity_per_read_thread)) != 0)
    {
        return result;
    }

#ifdef OS_LINUX
    if (DA_READ_BY_DIRECT_IO) {
        ctx->block_size = path_info->block_size;
        ctx->iocbs.alloc = path_info->read_io_depth;
        ctx->iocbs.pp = (struct iocb **)fc_malloc(sizeof(
                    struct iocb *) * ctx->iocbs.alloc);
        if (ctx->iocbs.pp == NULL) {
            return ENOMEM;
        }

        ctx->aio.max_event = path_info->read_io_depth;
        ctx->aio.events = (struct io_event *)fc_malloc(sizeof(
                    struct io_event) * ctx->aio.max_event);
        if (ctx->aio.events == NULL) {
            return ENOMEM;
        }

        ctx->aio.ctx = 0;
        if (io_setup(ctx->aio.max_event, &ctx->aio.ctx) != 0) {
            result = errno != 0 ? errno : ENOMEM;
            logError("file: "__FILE__", line: %d, "
                    "io_setup fail, errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
        ctx->aio.doing_count = 0;
    }

#endif

    return fc_create_thread(&tid, trunk_read_thread_func,
            ctx, SF_G_THREAD_STACK_SIZE);
}

static int init_thread_contexts(TrunkReadThreadContextArray *ctx_array,
        const DAStoragePathInfo *path_info)
{
    int result;
    TrunkReadThreadContext *ctx;
    TrunkReadThreadContext *end;
    
    end = ctx_array->contexts + ctx_array->count;
    for (ctx=ctx_array->contexts; ctx<end; ctx++) {
        ctx->indexes.path = path_info->store.index;
        if (ctx_array->count == 1) {
            ctx->indexes.thread = -1;
        } else {
            ctx->indexes.thread = ctx - ctx_array->contexts;
        }
        if ((result=init_thread_context(ctx, path_info)) != 0) {
            return result;
        }
    }

    return 0;
}

static int init_path_contexts(DAStoragePathArray *parray)
{
    DAStoragePathInfo *p;
    DAStoragePathInfo *end;
    TrunkReadThreadContext *thread_ctxs;
    TrunkReadPathContext *path_ctx;
    int result;

    end = parray->paths + parray->count;
    for (p=parray->paths; p<end; p++) {
        path_ctx = trunk_io_ctx.path_ctx_array.paths + p->store.index;
        if ((thread_ctxs=alloc_thread_contexts(
                        p->read_thread_count)) == NULL)
        {
            return ENOMEM;
        }

        path_ctx->reads.contexts = thread_ctxs;
        path_ctx->reads.count = p->read_thread_count;
        if ((result=init_thread_contexts(&path_ctx->reads, p)) != 0) {
            return result;
        }
    }

    return 0;
}

#ifdef OS_LINUX
static int rbpool_init_start()
{
    SFMemoryWatermark memory_watermark;
    DAStoragePathInfo **pp;
    DAStoragePathInfo **end;
    int path_count;
    int result;

    path_count = storage_config_path_count(&DA_STORE_CFG);
    memory_watermark.low = DA_STORE_CFG.aio_read_buffer.
        memory_watermark_low.value / path_count;
    memory_watermark.high = DA_STORE_CFG.aio_read_buffer.
        memory_watermark_high.value / path_count;
    if ((result=read_buffer_pool_init(DA_STORE_CFG.paths_by_index.count,
                    &memory_watermark)) != 0)
    {
        return result;
    }

    end = DA_STORE_CFG.paths_by_index.paths +
        DA_STORE_CFG.paths_by_index.count;
    for (pp=DA_STORE_CFG.paths_by_index.paths; pp<end; pp++) {
        if (*pp != NULL) {
            if ((result=read_buffer_pool_create((*pp)->store.index,
                            (*pp)->block_size)) != 0)
            {
                return result;
            }
        }
    }

    return read_buffer_pool_start(DA_STORE_CFG.aio_read_buffer.max_idle_time,
            DA_STORE_CFG.aio_read_buffer.reclaim_interval);
}
#endif

int trunk_read_thread_init()
{
    int result;

#ifdef OS_LINUX
    if (DA_READ_BY_DIRECT_IO) {
        if ((result=rbpool_init_start()) != 0) {
            return result;
        }
    }
#endif

    if ((result=alloc_path_contexts()) != 0) {
        return result;
    }

    if ((result=init_path_contexts(&DA_STORE_CFG.write_cache)) != 0) {
        return result;
    }
    if ((result=init_path_contexts(&DA_STORE_CFG.store_path)) != 0) {
        return result;
    }

    /*
       logInfo("trunk_io_ctx.path_ctx_array.count: %d",
               trunk_io_ctx.path_ctx_array.count);
     */
    return 0;
}

void trunk_read_thread_terminate()
{
}

int trunk_read_thread_push(const DATrunkSpaceInfo *space,
        const int read_bytes, DATrunkReadBuffer *rb,
        trunk_read_io_notify_func notify_func, void *notify_arg)
{
    TrunkReadPathContext *path_ctx;
    TrunkReadThreadContext *thread_ctx;
    DATrunkReadIOBuffer *iob;

    path_ctx = trunk_io_ctx.path_ctx_array.paths +
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

static int get_read_fd(TrunkReadThreadContext *ctx,
        DATrunkSpaceInfo *space, int *fd)
{
    char trunk_filename[PATH_MAX];
    int result;

    if ((*fd=trunk_fd_cache_get(&ctx->fd_cache,
                    space->id_info.id)) >= 0)
    {
        return 0;
    }

    dio_get_trunk_filename(space, trunk_filename, sizeof(trunk_filename));
#ifdef OS_LINUX
    if (DA_READ_BY_DIRECT_IO) {
        *fd = open(trunk_filename, O_RDONLY | O_DIRECT);
    } else {
        *fd = open(trunk_filename, O_RDONLY);
    }
#else
    *fd = open(trunk_filename, O_RDONLY);
#endif
    if (*fd < 0) {
        result = errno != 0 ? errno : EACCES;
        logError("file: "__FILE__", line: %d, "
                "open file \"%s\" fail, errno: %d, error info: %s",
                __LINE__, trunk_filename, result, STRERROR(result));
        return result;
    }

    trunk_fd_cache_add(&ctx->fd_cache, space->id_info.id, *fd);
    return 0;
}

#ifdef OS_LINUX

static inline int prepare_read_slice(TrunkReadThreadContext *ctx,
        DATrunkReadIOBuffer *iob)
{
    int64_t new_offset;
    int offset;
    int read_bytes;
    int result;
    int fd;
    bool new_alloced;

    new_offset = MEM_ALIGN_FLOOR(iob->space.offset, ctx->block_size);
    read_bytes = MEM_ALIGN_CEIL(iob->read_bytes, ctx->block_size);
    offset = iob->space.offset - new_offset;
    if (offset > 0) {
        if (new_offset + read_bytes < iob->space.offset +
                iob->read_bytes)
        {
            read_bytes += ctx->block_size;
        }
    }

    if (iob->rb->aio_buffer != NULL && iob->rb->aio_buffer->
            size < read_bytes)
    {
        logWarning("file: "__FILE__", line: %d, "
                "buffer size %d is too small, required size: %d",
                __LINE__, iob->rb->aio_buffer->size, read_bytes);

        read_buffer_pool_free(iob->rb->aio_buffer);
        iob->rb->aio_buffer = NULL;
    }

    if (iob->rb->aio_buffer == NULL) {
        iob->rb->aio_buffer = read_buffer_pool_alloc(
                ctx->indexes.path, read_bytes);
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
    logInfo("space.offset: %"PRId64", new_offset: %"PRId64", "
            "offset: %d, read_bytes: %d, size: %d", iob->space.offset,
            new_offset, offset, read_bytes, iob->rb->aio_buffer->size);
            */

    if ((result=get_read_fd(ctx, &iob->space, &fd)) != 0) {
        if (new_alloced) {
            read_buffer_pool_free(iob->rb->aio_buffer);
            iob->rb->aio_buffer = NULL;
        }
        return result;
    }

    io_prep_pread(&iob->iocb, fd, iob->rb->aio_buffer->buff,
            iob->rb->aio_buffer->read_bytes, new_offset);
    iob->iocb.data = iob;
    ctx->iocbs.pp[ctx->iocbs.count++] = &iob->iocb;
    return 0;
}

static int consume_queue(TrunkReadThreadContext *ctx)
{
    struct fc_queue_info qinfo;
    DATrunkReadIOBuffer *iob;
    int target_count;
    int count;
    int remain;
    int n;
    int result;

    fc_queue_pop_to_queue_ex(&ctx->queue, &qinfo, ctx->aio.doing_count == 0);
    if (qinfo.head == NULL) {
        return 0;
    }

    target_count = ctx->aio.max_event - ctx->aio.doing_count;
    ctx->iocbs.count = 0;
    iob = (DATrunkReadIOBuffer *)qinfo.head;
    do {
        if ((result=prepare_read_slice(ctx, iob)) != 0) {
            return result;
        }

        iob = iob->next;
    } while (iob != NULL && ctx->iocbs.count < target_count);

    count = 0;
    while ((remain=ctx->iocbs.count - count) > 0) {
        if ((n=io_submit(ctx->aio.ctx, remain,
                        ctx->iocbs.pp + count)) <= 0)
        {
            result = errno != 0 ? errno : ENOMEM;
            if (result == EINTR) {
                continue;
            }

            logError("file: "__FILE__", line: %d, "
                    "io_submiti return %d != %d, "
                    "errno: %d, error info: %s",
                    __LINE__, count, ctx->iocbs.count,
                    result, STRERROR(result));
            return result;
        }

        count += n;
    }

    ctx->aio.doing_count += ctx->iocbs.count;
    if (iob != NULL) {
        qinfo.head = iob;
        fc_queue_push_queue_to_head_silence(&ctx->queue, &qinfo);
    }
    return 0;
}

static int process_aio(TrunkReadThreadContext *ctx)
{
    struct timespec tms;
    DATrunkReadIOBuffer *iob;
    struct io_event *event;
    struct io_event *end;
    char trunk_filename[PATH_MAX];
    bool full;
    int count;
    int result;

    full = ctx->aio.doing_count >= ctx->aio.max_event;
    while (1) {
        if (full) {
            tms.tv_sec = 1;
            tms.tv_nsec = 0;
        } else {
            tms.tv_sec = 0;
            if (ctx->aio.doing_count < 10) {
                tms.tv_nsec = ctx->aio.doing_count * 1000 * 1000;
            } else {
                tms.tv_nsec = 10 * 1000 * 1000;
            }
        }
        count = io_getevents(ctx->aio.ctx, 1, ctx->aio.
                max_event, ctx->aio.events, &tms);
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

            logCrit("file: "__FILE__", line: %d, "
                    "io_getevents fail, errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
    }

    end = ctx->aio.events + count;
    for (event=ctx->aio.events; event<end; event++) {
        iob = (DATrunkReadIOBuffer *)event->data;
        if (event->res == iob->rb->aio_buffer->read_bytes) {
            result = 0;
        } else {
            trunk_fd_cache_delete(&ctx->fd_cache,
                    iob->space.id_info.id);

            if ((int)event->res < 0) {
                result = -1 * event->res;
            } else {
                result = EBUSY;
            }
            dio_get_trunk_filename(&iob->space, trunk_filename,
                    sizeof(trunk_filename));
            logError("file: "__FILE__", line: %d, "
                    "read trunk file: %s fail, offset: %u, "
                    "expect length: %d, read return: %d, errno: %d, "
                    "error info: %s", __LINE__, trunk_filename,
                    iob->space.offset - iob->rb->aio_buffer->offset,
                    iob->rb->aio_buffer->read_bytes, (int)event->res,
                    result, STRERROR(result));
        }

        iob->notify.func(iob, result);
        fast_mblock_free_object(&ctx->mblock, iob);
    }
    ctx->aio.doing_count -= count;

    return 0;
}

static inline int process(TrunkReadThreadContext *ctx)
{
    int result;

    if ((result=consume_queue(ctx)) != 0) {
        return result;
    }

    if (ctx->aio.doing_count <= 0) {
        return 0;
    }

    return process_aio(ctx);
}

#endif

static int do_read_slice(TrunkReadThreadContext *ctx, DATrunkReadIOBuffer *iob)
{
    int fd;
    int remain;
    int bytes;
    int result;

    if ((result=get_read_fd(ctx, &iob->space, &fd)) != 0) {
        return result;
    }

    iob->rb->buffer.length = 0;
    remain = iob->read_bytes;
    while (remain > 0) {
        bytes = pread(fd, iob->rb->buffer.buff + iob->rb->buffer.length,
                remain, iob->space.offset + iob->rb->buffer.length);
        if (bytes <= 0) {
            char trunk_filename[PATH_MAX];

            result = errno != 0 ? errno : EIO;
            if (result == EINTR) {
                continue;
            }

            trunk_fd_cache_delete(&ctx->fd_cache,
                    iob->space.id_info.id);

            dio_get_trunk_filename(&iob->space, trunk_filename,
                    sizeof(trunk_filename));
            logError("file: "__FILE__", line: %d, "
                    "read trunk file: %s fail, offset: %u, "
                    "errno: %d, error info: %s", __LINE__, trunk_filename,
                    iob->space.offset + iob->rb->buffer.length,
                    result, STRERROR(result));
            return result;
        }

        iob->rb->buffer.length += bytes;
        remain -= bytes;
    }

    return 0;
}

static void normal_read_loop(TrunkReadThreadContext *ctx)
{
    int result;
    DATrunkReadIOBuffer *iob;

    while (SF_G_CONTINUE_FLAG) {
        if ((iob=(DATrunkReadIOBuffer *)fc_queue_pop(&ctx->queue)) == NULL) {
            continue;
        }

        if ((result=do_read_slice(ctx, iob)) != 0) {
            logError("file: "__FILE__", line: %d, "
                    "slice read fail, result: %d",
                    __LINE__, result);
        }

        if (iob->notify.func != NULL) {
            iob->notify.func(iob, result);
        }
        fast_mblock_free_object(&ctx->mblock, iob);
    }
}

static void *trunk_read_thread_func(void *arg)
{
    TrunkReadThreadContext *ctx;
#ifdef OS_LINUX
    int len;
    char thread_name[16];
#endif

    ctx = (TrunkReadThreadContext *)arg;

#ifdef OS_LINUX
    len = snprintf(thread_name, sizeof(thread_name),
            "dio-p%02d-r", ctx->indexes.path);
    if (ctx->indexes.thread >= 0) {
        snprintf(thread_name + len, sizeof(thread_name) - len,
                "[%d]", ctx->indexes.thread);
    }
    prctl(PR_SET_NAME, thread_name);

    if (DA_READ_BY_DIRECT_IO) {
        while (SF_G_CONTINUE_FLAG) {
            if (process(ctx) != 0) {
                sf_terminate_myself();
                break;
            }
        }
    } else {
        normal_read_loop(ctx);
    }
#else
    normal_read_loop(ctx);
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
        const DAStoragePathInfo *path_info)
{
#ifdef OS_LINUX
    int aligned_size;

    if (DA_READ_BY_DIRECT_IO) {
        aligned_size = op_ctx->storage->size + path_info->block_size * 2;
        if (op_ctx->rb.aio_buffer != NULL && op_ctx->rb.
                aio_buffer->size < aligned_size)
        {
            AlignedReadBuffer *new_buffer;

            new_buffer = read_buffer_pool_alloc(path_info->
                    store.index, aligned_size);
            if (new_buffer == NULL) {
                return ENOMEM;
            }

            read_buffer_pool_free(op_ctx->rb.aio_buffer);
            op_ctx->rb.aio_buffer = new_buffer;
        }

        return 0;
    }
#endif

    if (op_ctx->rb.buffer.alloc_size < op_ctx->storage->size) {
        char *buff;
        int buffer_size;

        buffer_size = op_ctx->rb.buffer.alloc_size * 2;
        while (buffer_size < op_ctx->storage->size) {
            buffer_size *= 2;
        }
        buff = (char *)fc_malloc(buffer_size);
        if (buff == NULL) {
            return ENOMEM;
        }

        free(op_ctx->rb.buffer.buff);
        op_ctx->rb.buffer.buff = buff;
        op_ctx->rb.buffer.alloc_size = buffer_size;
    }

    return 0;
}

int da_slice_read(DASynchronizedReadContext *ctx)
{
    int result;
    DATrunkSpaceInfo space;
    DATrunkFileInfo *trunk;

    if ((trunk=trunk_hashtable_get(ctx->op_ctx.storage->trunk_id)) == NULL) {
        return ENOENT;
    }

    if ((result=check_alloc_buffer(&ctx->op_ctx, trunk->
                    allocator->path_info)) != 0)
    {
        return result;
    }

    ctx->sctx.result = INT16_MIN;
    space.store = &trunk->allocator->path_info->store;
    space.id_info = trunk->id_info;
    space.offset = ctx->op_ctx.storage->offset;
    space.size = ctx->op_ctx.storage->size;
    if ((result=trunk_read_thread_push(&space, ctx->op_ctx.storage->length,
                    &ctx->op_ctx.rb, slice_read_done, &ctx->sctx)) != 0)
    {
        return result;
    }

    PTHREAD_MUTEX_LOCK(&ctx->sctx.lcp.lock);
    while (ctx->sctx.result == INT16_MIN && SF_G_CONTINUE_FLAG) {
        pthread_cond_wait(&ctx->sctx.lcp.cond,
                &ctx->sctx.lcp.lock);
    }
    result = ctx->sctx.result == INT16_MIN ? EINTR : ctx->sctx.result;
    PTHREAD_MUTEX_UNLOCK(&ctx->sctx.lcp.lock);

    return result;
}
