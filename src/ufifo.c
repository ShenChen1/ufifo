#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
#include "fdlock.h"
#include "mutex.h"
#include "kfifo.h"
#include "ufifo.h"
#include "utils.h"

#define UFIFO_MAGIC (0xf1f0f1f0)

struct ufifo {
    unsigned int    magic;

    char            name[NAME_MAX];
    struct __kfifo *kfifo;
    ufifo_hook_t    hook;

    int             shm_fd;
    unsigned int    shm_size;
    void           *shm_mem;

    void           *lock;
    int           (*lock_init)(ufifo_t *ufifo);
    int           (*lock_deinit)(ufifo_t *ufifo);
    int           (*lock_acquire)(ufifo_t *ufifo);
    int           (*lock_release)(ufifo_t *ufifo);
};

static inline int __fdlock_acquire(ufifo_t *ufifo)
{
    char path[NAME_MAX];
    snprintf(path, sizeof(path), "/var/lock/%s.lock", ufifo->name);
    return fdlock_acquire(path, (fdlock_t **)&ufifo->lock);
}

static inline int __fdlock_release(ufifo_t *ufifo)
{
    return fdlock_release((fdlock_t **)ufifo->lock);
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

static inline int ufifo_lock_acquire(ufifo_t *ufifo)
{
    return ufifo->lock_acquire ? ufifo->lock_acquire(ufifo) : 0;
}

static inline int ufifo_lock_release(ufifo_t *ufifo)
{
    return ufifo->lock_release ? ufifo->lock_release(ufifo) : 0;
}

static inline int ufifo_lock_init(ufifo_t *ufifo, ufifo_lock_e lock)
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

static inline int ufifo_lock_deinit(ufifo_t *ufifo)
{
    return ufifo->lock_deinit ? ufifo->lock_deinit(ufifo) : 0;
}

static inline int ufifo_hook_init(ufifo_t *ufifo, ufifo_hook_t *hook)
{
    ufifo->hook.recsize = hook->recsize;
    ufifo->hook.rectag = hook->rectag;
    return 0;
}

static int ufifo_init_from_shm(ufifo_t *ufifo)
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
    ufifo->shm_size -= sizeof(struct __kfifo);
    ufifo->kfifo = (void *)((char *)ufifo->shm_mem + ufifo->shm_size);

end:
    return ret;
}

static int ufifo_init_from_user(ufifo_t *ufifo)
{
    int ret = 0;

    if (!ufifo->shm_size) {
        return -EINVAL;
    }

    ufifo->shm_size += sizeof(struct __kfifo);
    ret = ftruncate(ufifo->shm_fd, ufifo->shm_size);
    if (ufifo->shm_fd < 0) {
        ret = -errno;
        goto end;
    }

    ufifo->shm_mem = mmap(NULL, ufifo->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->shm_fd, 0);
    ufifo->shm_size -= sizeof(struct __kfifo);
    ufifo->kfifo = (void *)((char *)ufifo->shm_mem + ufifo->shm_size);
    ret = kfifo_init(ufifo->kfifo, ufifo->shm_mem, ufifo->shm_size);

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

    ret |= ufifo_hook_init(ufifo, &init->hook);
    ret |= ufifo_lock_init(ufifo, init->opt);
    if (ret < 0) {
        goto err1;
    }

    strncpy(ufifo->name, name, sizeof(ufifo->name));
    ret = ufifo_lock_acquire(ufifo);
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
    ret = (init->opt == UFIFO_OPT_ALLOC) ? ufifo_init_from_user(ufifo) : ufifo_init_from_shm(ufifo);
    if (ret < 0) {
        goto err4;
    }

    *handle = ufifo;
    ufifo_lock_release(ufifo);
    return 0;

err4:
    close(ufifo->shm_fd);
    shm_unlink(ufifo->name);
err3:
    ufifo_lock_release(ufifo);
err2:
    ufifo_lock_deinit(ufifo);
err1:
    free(ufifo);
    return ret;
}

int ufifo_close(ufifo_t *handle)
{
    int ret;

    ret = ufifo_lock_acquire(handle);
    if (ret < 0) {
        return ret;
    }

    munmap(handle->shm_mem, handle->shm_size);
    close(handle->shm_fd);

    ufifo_lock_release(handle);
    free(handle);

    return 0;
}

static unsigned int __ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len = handle->kfifo->in == handle->kfifo->out ? 0 : 1;

    if (len && handle->hook.recsize) {
        len = handle->hook.recsize(
            handle->kfifo->data + (handle->kfifo->out & handle->kfifo->mask),
            handle->kfifo->mask - (handle->kfifo->out & handle->kfifo->mask) + 1,
            handle->kfifo->data);
    }

    return len;
}

static unsigned int __ufifo_peek_tag(ufifo_t *handle)
{
    unsigned int ret = 0;

    if (handle->hook.rectag) {
        ret = handle->hook.rectag(
            handle->kfifo->data + (handle->kfifo->out & handle->kfifo->mask),
            handle->kfifo->mask - (handle->kfifo->out & handle->kfifo->mask) + 1,
            handle->kfifo->data);
    }

    return ret;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int ufifo_size(ufifo_t *handle)
{
    return handle->kfifo->mask + 1;
}

void ufifo_reset(ufifo_t *handle)
{
    ufifo_lock_acquire(handle);
    handle->kfifo->out = handle->kfifo->in = 0;
    ufifo_lock_release(handle);
}

unsigned int ufifo_len(ufifo_t *handle)
{
    unsigned int len;

    ufifo_lock_acquire(handle);
    len = handle->kfifo->in - handle->kfifo->out;
    ufifo_lock_release(handle);

    return len;
}

void ufifo_skip(ufifo_t *handle)
{
    ufifo_lock_acquire(handle);
    handle->kfifo->out += __ufifo_peek_len(handle);
    ufifo_lock_release(handle);
}

unsigned int ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len;

    ufifo_lock_acquire(handle);
    len = __ufifo_peek_len(handle);
    ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size)
{
    unsigned int len;

    ufifo_lock_acquire(handle);
    len = handle->kfifo->in - handle->kfifo->out;
    if (handle->kfifo->mask + 1 - len < size) {
        len = 0;
        goto end;
    }

    len = kfifo_in(handle->kfifo, buf, size);
end:
    ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size)
{
    unsigned int len;

    ufifo_lock_acquire(handle);
    len = __ufifo_peek_len(handle);
    size = len == 1 ? size : min(size, len);
    len = kfifo_out(handle->kfifo, buf, size);
    ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size)
{
    unsigned int len;

    ufifo_lock_acquire(handle);
    len = __ufifo_peek_len(handle);
    size = len == 1 ? size : min(size, len);
    len = kfifo_out_peek(handle->kfifo, buf, size);
    ufifo_lock_release(handle);

    return len;
}

void ufifo_oldest(ufifo_t *handle, unsigned int tag)
{
    unsigned int len;

    ufifo_lock_acquire(handle);
    while(1) {
        len = __ufifo_peek_len(handle);
        if (!len) {
            break;
        }
        if (__ufifo_peek_tag(handle) == tag) {
            break;
        }
        handle->kfifo->out += len;
    }
    ufifo_lock_release(handle);
}

void ufifo_newest(ufifo_t *handle, unsigned int tag)
{
    unsigned int len;
    unsigned int final = 0, tmp;

    ufifo_lock_acquire(handle);
    tmp = handle->kfifo->out;
    while(1) {
        len = __ufifo_peek_len(handle);
        if (!len) {
            handle->kfifo->out = final ? final : tmp;
            break;
        }
        if (__ufifo_peek_tag(handle) == tag) {
            final = handle->kfifo->out;
        }
        handle->kfifo->out += len;
        tmp = handle->kfifo->out;
    }
    ufifo_lock_release(handle);
}