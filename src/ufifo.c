#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>       /* For mode constants */
#include <fcntl.h>          /* For O_* constants */
#include "fdlock.h"
#include "mutex.h"
#include "kfifo.h"
#include "ufifo.h"
#include "utils.h"

#define UFIFO_DEBUG (1)
#define UFIFO_MAGIC (0xf1f0f1f0)

#define UFIFO_CHECK_HANDLE_FUNC(handle) \
    assert((handle)); \
    assert((handle)->magic == UFIFO_MAGIC);

struct ufifo {
    unsigned int    magic;

    char            name[NAME_MAX];
    kfifo_t        *kfifo;
    ufifo_hook_t    hook;

    int             shm_fd;
    unsigned int    shm_size;
    void           *shm_mem;

    void           *lock;
    int           (*lock_init)(ufifo_t *ufifo);
    int           (*lock_deinit)(ufifo_t *ufifo);
    int           (*lock_acquire)(ufifo_t *ufifo);
    int           (*lock_release)(ufifo_t *ufifo);

    sem_t          *bsem_rd;
    sem_t          *bsem_wr;
};

static inline int __fdlock_acquire(ufifo_t *ufifo)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/var/lock/%s.lock", ufifo->name);
    return fdlock_acquire(path, (fdlock_t **)&ufifo->lock);
}

static inline int __fdlock_release(ufifo_t *ufifo)
{
    return fdlock_release((fdlock_t **)&ufifo->lock);
}

static inline int __mutex_init(ufifo_t *ufifo)
{
    return mutex_init((mutex_t **)&ufifo->lock);
}

static inline int __mutex_deinit(ufifo_t *ufifo)
{
    return mutex_deinit((mutex_t *)ufifo->lock);
}

static inline int __mutex_acquire(ufifo_t *ufifo)
{
    return mutex_acquire((mutex_t *)ufifo->lock);
}

static inline int __mutex_release(ufifo_t *ufifo)
{
    return mutex_release((mutex_t *)ufifo->lock);
}

static inline int __ufifo_lock_acquire(ufifo_t *ufifo)
{
    return ufifo->lock_acquire ? ufifo->lock_acquire(ufifo) : 0;
}

static inline int __ufifo_lock_release(ufifo_t *ufifo)
{
    return ufifo->lock_release ? ufifo->lock_release(ufifo) : 0;
}

static int __ufifo_bsem_init(sem_t *bsem, unsigned int value)
{
    return sem_init(bsem, 1, value);
}

static int __ufifo_bsem_deinit(sem_t *bsem)
{
    return sem_destroy(bsem);
}

static int __ufifo_bsem_wait(sem_t *bsem, ufifo_t *ufifo)
{
    int ret;
    int value = 0;

    while (1) {
        ret = sem_getvalue(bsem, &value);
        if (ret) {
            assert(0);
        }
        if (value == 0) {
            __ufifo_lock_release(ufifo);
            ret = sem_wait(bsem);
            __ufifo_lock_acquire(ufifo);
            break;
        }
        ret = sem_wait(bsem);
        if (ret) {
            assert(0);
        }
    }

    return ret;
}

static int __ufifo_bsem_post(sem_t *bsem)
{
    return sem_post(bsem);
}

static inline int __ufifo_lock_init(ufifo_t *ufifo, ufifo_lock_e lock)
{
    if (lock == UFIFO_LOCK_FDLOCK) {
        ufifo->lock_init = NULL;
        ufifo->lock_deinit = NULL;
        ufifo->lock_acquire = __fdlock_acquire;
        ufifo->lock_release = __fdlock_release;
    } else if (lock == UFIFO_LOCK_MUTEX) {
        ufifo->lock_init = __mutex_init;
        ufifo->lock_deinit = __mutex_deinit;
        ufifo->lock_acquire = __mutex_acquire;
        ufifo->lock_release = __mutex_release;
    } else {
        ufifo->lock_init = NULL;
        ufifo->lock_deinit = NULL;
        ufifo->lock_acquire = NULL;
        ufifo->lock_release = NULL;
    }

    return ufifo->lock_init ? ufifo->lock_init(ufifo) : 0;
}

static inline int __ufifo_lock_deinit(ufifo_t *ufifo)
{
    return ufifo->lock_deinit ? ufifo->lock_deinit(ufifo) : 0;
}

static inline int __ufifo_hook_init(ufifo_t *ufifo, ufifo_hook_t *hook)
{
    ufifo->hook.recsize = hook->recsize;
    ufifo->hook.rectag = hook->rectag;
    return 0;
}

static int __ufifo_init_from_shm(ufifo_t *ufifo)
{
    int ret = 0;
    struct stat stat;

    ret = fstat(ufifo->shm_fd, &stat);
    if (ufifo->shm_fd < 0) {
        ret = -errno;
        goto end;
    }

    ufifo->shm_size = stat.st_size;
    ufifo->shm_mem = mmap(NULL, ufifo->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->shm_fd, 0);
    ufifo->shm_size -= (sizeof(kfifo_t) + 2 * sizeof(sem_t));
    ufifo->kfifo = (void *)((char *)ufifo->shm_mem + ufifo->shm_size);
    ufifo->bsem_wr = (void *)((char *)ufifo->kfifo + sizeof(kfifo_t));
    ufifo->bsem_rd = (void *)((char *)ufifo->bsem_wr + sizeof(sem_t));

end:
    return ret;
}

static int __ufifo_init_from_user(ufifo_t *ufifo)
{
    int ret = 0;

    if (!ufifo->shm_size) {
        return -EINVAL;
    }

    ufifo->shm_size += (sizeof(kfifo_t) + 2 * sizeof(sem_t));
    ret = ftruncate(ufifo->shm_fd, ufifo->shm_size);
    if (ufifo->shm_fd < 0) {
        ret = -errno;
        goto end;
    }

    ufifo->shm_mem = mmap(NULL, ufifo->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->shm_fd, 0);
    ufifo->shm_size -= (sizeof(kfifo_t) + 2 * sizeof(sem_t));
    ufifo->kfifo = (void *)((char *)ufifo->shm_mem + ufifo->shm_size);
    ret |= kfifo_init(ufifo->kfifo, ufifo->shm_mem, ufifo->shm_size);
    ufifo->bsem_wr = (void *)((char *)ufifo->kfifo + sizeof(kfifo_t));
    ret |= __ufifo_bsem_init(ufifo->bsem_wr, 0);
    ufifo->bsem_rd = (void *)((char *)ufifo->bsem_wr + sizeof(sem_t));
    ret |= __ufifo_bsem_init(ufifo->bsem_rd, 0);

end:
    return ret;
}

int ufifo_open(char *name, ufifo_init_t *init, ufifo_t **handle)
{
    int ret = 0;
    ufifo_t *ufifo = NULL;

    if (name == NULL || init == NULL) {
        return -EINVAL;
    }

    if (init->opt >= UFIFO_OPT_MAX || init->lock >= UFIFO_LOCK_MAX) {
        return -EINVAL;
    }

    ufifo = calloc(1, sizeof(ufifo_t));
    if (ufifo == NULL) {
        return -ENOMEM;
    }

    ret |= __ufifo_hook_init(ufifo, &init->hook);
    ret |= __ufifo_lock_init(ufifo, init->lock);
    if (ret < 0) {
        goto err1;
    }

    strncpy(ufifo->name, name, sizeof(ufifo->name));
    ret = __ufifo_lock_acquire(ufifo);
    if (ret < 0) {
        goto err2;
    }

    int oflag = (init->opt == UFIFO_OPT_ALLOC) ? (O_RDWR | O_CREAT) : (O_RDWR);
    ufifo->shm_fd = shm_open(name, oflag, (S_IRUSR | S_IWUSR));
    if (ufifo->shm_fd < 0) {
        ret = -errno;
        goto err3;
    }

    ufifo->shm_size = init->alloc.size;
    ret = (init->opt == UFIFO_OPT_ALLOC) ?
        __ufifo_init_from_user(ufifo) :
        __ufifo_init_from_shm(ufifo);
    if (ret < 0) {
        goto err4;
    }

    ufifo->magic = UFIFO_MAGIC;
    *handle = ufifo;
    __ufifo_lock_release(ufifo);
    return 0;

err4:
    close(ufifo->shm_fd);
    shm_unlink(ufifo->name);
err3:
    __ufifo_lock_release(ufifo);
err2:
    __ufifo_lock_deinit(ufifo);
err1:
    free(ufifo);
    return ret;
}

int ufifo_close(ufifo_t *handle)
{
    int ret;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    ret = __ufifo_lock_acquire(handle);
    if (ret < 0) {
        return ret;
    }

    __ufifo_bsem_deinit(handle->bsem_wr);
    __ufifo_bsem_deinit(handle->bsem_rd);
    munmap(handle->shm_mem, handle->shm_size);
    close(handle->shm_fd);

    __ufifo_lock_release(handle);
    __ufifo_lock_deinit(handle);
    free(handle);

    return 0;
}

static unsigned int __ufifo_unused_len(ufifo_t *handle)
{
    unsigned int len;

    len = handle->kfifo->in - handle->kfifo->out;
    return handle->kfifo->mask + 1 - len;
}

static unsigned int __ufifo_peek_len(ufifo_t *handle, unsigned int offset)
{
    unsigned int len = handle->kfifo->in == offset ? 0 : 1;

    if (len && handle->hook.recsize) {
        offset &= handle->kfifo->mask;
        len = handle->hook.recsize(
            handle->kfifo->data + offset,
            handle->kfifo->mask - offset + 1,
            handle->kfifo->data);
    }

    return len;
}

static unsigned int __ufifo_peek_tag(ufifo_t *handle, unsigned int offset)
{
    unsigned int ret = 0;

    if (handle->hook.rectag) {
        offset &= handle->kfifo->mask;
        ret = handle->hook.rectag(
            handle->kfifo->data + offset,
            handle->kfifo->mask - offset + 1,
            handle->kfifo->data);
    }

    return ret;
}

unsigned int ufifo_size(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return handle->kfifo->mask + 1;
}

void ufifo_reset(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    handle->kfifo->out = handle->kfifo->in = 0;
    __ufifo_lock_release(handle);
}

unsigned int ufifo_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    len = handle->kfifo->in - handle->kfifo->out;
    __ufifo_lock_release(handle);

    return len;
}

void ufifo_skip(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    handle->kfifo->out += __ufifo_peek_len(handle, handle->kfifo->out);
    __ufifo_lock_release(handle);
}

unsigned int ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    len = __ufifo_peek_len(handle, handle->kfifo->out);
    __ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    len = __ufifo_unused_len(handle);
    if (len < size) {
        len = 0;
        goto end;
    }

    len = kfifo_in(handle->kfifo, buf, size);
end:
    __ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    len = __ufifo_peek_len(handle, handle->kfifo->out);
    if (len == 0) {
        goto end;
    }
    size = handle->hook.recsize ? min(size, len) : size;
    len = kfifo_out(handle->kfifo, buf, size);
end:
    __ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    len = __ufifo_peek_len(handle, handle->kfifo->out);
    if (len == 0) {
        goto end;
    }
    size = handle->hook.recsize ? min(size, len) : size;
    len = kfifo_out_peek(handle->kfifo, buf, size);
end:
    __ufifo_lock_release(handle);

    return len;
}

int ufifo_oldest(ufifo_t *handle, unsigned int tag)
{
    int ret;
    unsigned int len, tmp;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    tmp = handle->kfifo->out;
    while(1) {
        len = __ufifo_peek_len(handle, tmp);
        if (!len) {
            ret = -ESPIPE;
            break;
        }
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            ret = 0;
            break;
        }
        tmp += len;
    }
    handle->kfifo->out = tmp;
    __ufifo_lock_release(handle);

    return ret;
}

int ufifo_newest(ufifo_t *handle, unsigned int tag)
{
    int ret;
    unsigned int len, tmp;
    unsigned int final = 0;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    tmp = handle->kfifo->out;
    while(1) {
        len = __ufifo_peek_len(handle, tmp);
        if (!len) {
            tmp = final ? final : tmp;
            ret = final ? 0 : -ESPIPE;
            break;
        }
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            final = tmp;
        }
        tmp += len;
    }
    handle->kfifo->out = tmp;
    __ufifo_lock_release(handle);

    return ret;
}

unsigned int ufifo_put_ex(ufifo_t *handle, void *buf, unsigned int size)
{
    int ret;
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    while (1) {
        len = __ufifo_unused_len(handle);
        if (len < size) {
            ret = __ufifo_bsem_wait(handle->bsem_wr, handle);
            if (ret) {
                len = 0;
                goto end;
            }
        } else {
            break;
        }
    }
    len = kfifo_in(handle->kfifo, buf, size);
    __ufifo_bsem_post(handle->bsem_rd);
end:
    __ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_get_ex(ufifo_t *handle, void *buf, unsigned int size)
{
    int ret;
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    while (1) {
        len = __ufifo_peek_len(handle, handle->kfifo->out);
        if (len == 0) {
            ret = __ufifo_bsem_wait(handle->bsem_rd, handle);
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }
    size = handle->hook.recsize ? min(size, len) : size;
    len = kfifo_out(handle->kfifo, buf, size);
    __ufifo_bsem_post(handle->bsem_wr);
end:
    __ufifo_lock_release(handle);

    return len;
}