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
#include "dict.h"
#include "kfifo.h"
#include "ufifo.h"
#include "utils.h"

#define UFIFO_DEBUG (0)
#define UFIFO_MAGIC (0xf1f0f1f0)

#if UFIFO_DEBUG
#define UFIFO_CHECK_HANDLE_FUNC(handle) \
    assert((handle)); \
    assert((handle)->magic == UFIFO_MAGIC);
#else
#define UFIFO_CHECK_HANDLE_FUNC(handle)
#endif

typedef void * lock_t;

struct ufifo {
#if UFIFO_DEBUG
    unsigned int    magic;
#endif
    char            name[NAME_MAX];
    kfifo_t        *kfifo;
    ufifo_hook_t    hook;

    int             shm_fd;
    unsigned int    shm_size;
    void           *shm_mem;

    lock_t          lock;
    int           (*lock_init)(lock_t *lock);
    int           (*lock_deinit)(lock_t *lock);
    int           (*lock_acquire)(lock_t *lock);
    int           (*lock_release)(lock_t *lock);

    sem_t          *bsem_rd;
    sem_t          *bsem_wr;
};

static mutex_t *s_mod_lock = NULL;
static dict_t *s_mod_dict = NULL;

static void __attribute__((constructor)) __module_init()
{
    mutex_init(&s_mod_lock);
    s_mod_dict = dictCreate(dictStringOps(NULL), dictIntOps(NULL));
}

static void __attribute__((destructor)) __module_deinit()
{
    dictDestroy(s_mod_dict);
    mutex_deinit(s_mod_lock);
}

static inline int __fdlock_acquire(lock_t *lock)
{
    char path[PATH_MAX];
    ufifo_t *ufifo = container_of(lock, ufifo_t, lock);
    snprintf(path, sizeof(path), "/var/lock/%s.lock", ufifo->name);
    return fdlock_acquire(path, (fdlock_t **)lock);
}

static inline int __fdlock_release(lock_t *lock)
{
    return fdlock_release((fdlock_t **)lock);
}

static inline int __mutex_init(lock_t *lock)
{
    const void *mutex = NULL;
    ufifo_t *ufifo = container_of(lock, ufifo_t, lock);
    mutex_acquire(s_mod_lock);
    mutex = dictGet(s_mod_dict, ufifo->name);
    if (!mutex) {
        mutex_init((mutex_t **)lock);
        dictSet(s_mod_dict, ufifo->name, *lock);
    } else {
        *lock = (lock_t)mutex;
    }
    mutex_release(s_mod_lock);
    return 0;
}

static inline int __mutex_deinit(lock_t *lock)
{
    ufifo_t *ufifo = container_of(lock, ufifo_t, lock);
    mutex_acquire(s_mod_lock);
    dictSet(s_mod_dict, ufifo->name, NULL);
    mutex_release(s_mod_lock);
    return mutex_deinit((mutex_t *)*lock);
}

static inline int __mutex_acquire(lock_t *lock)
{
    return mutex_acquire((mutex_t *)*lock);
}

static inline int __mutex_release(lock_t *lock)
{
    return mutex_release((mutex_t *)*lock);
}

static inline int __ufifo_lock_acquire(lock_t *lock)
{
    ufifo_t *ufifo = container_of(lock, ufifo_t, lock);
    return ufifo->lock_acquire ? ufifo->lock_acquire(lock) : 0;
}

static inline int __ufifo_lock_release(lock_t *lock)
{
    ufifo_t *ufifo = container_of(lock, ufifo_t, lock);
    return ufifo->lock_release ? ufifo->lock_release(lock) : 0;
}

static inline int __ufifo_lock_init(lock_t *lock, ufifo_lock_e type)
{
    ufifo_t *ufifo = container_of(lock, ufifo_t, lock);

    if (type == UFIFO_LOCK_FDLOCK) {
        ufifo->lock_init = NULL;
        ufifo->lock_deinit = NULL;
        ufifo->lock_acquire = __fdlock_acquire;
        ufifo->lock_release = __fdlock_release;
    } else if (type == UFIFO_LOCK_MUTEX) {
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

    return ufifo->lock_init ? ufifo->lock_init(lock) : 0;
}

static inline int __ufifo_lock_deinit(lock_t *lock)
{
    ufifo_t *ufifo = container_of(lock, ufifo_t, lock);
    return ufifo->lock_deinit ? ufifo->lock_deinit(lock) : 0;
}

static int __ufifo_bsem_init(sem_t *bsem, unsigned int value)
{
    return sem_init(bsem, 1, value);
}

static int __ufifo_bsem_deinit(sem_t *bsem)
{
    return sem_destroy(bsem);
}

static int __ufifo_bsem_wait(sem_t *bsem, lock_t *lock)
{
    int ret;

    __ufifo_lock_release(lock);
    ret = sem_wait(bsem);
    __ufifo_lock_acquire(lock);

    return ret;
}

static int __ufifo_bsem_post(sem_t *bsem)
{
    sem_trywait(bsem);
    return sem_post(bsem);
}

static inline int __ufifo_hook_init(ufifo_t *ufifo, ufifo_hook_t *hook)
{
    ufifo->hook.recsize = hook->recsize;
    ufifo->hook.rectag = hook->rectag;
    ufifo->hook.recput = hook->recput;
    ufifo->hook.recget = hook->recget;
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
    ret |= kfifo_init(ufifo->kfifo, ufifo->shm_size);
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
    ret |= __ufifo_lock_init(&ufifo->lock, init->lock);
    if (ret < 0) {
        goto err1;
    }

    strncpy(ufifo->name, name, sizeof(ufifo->name));
    ret = __ufifo_lock_acquire(&ufifo->lock);
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

#if UFIFO_DEBUG
    ufifo->magic = UFIFO_MAGIC;
#endif
    *handle = ufifo;
    __ufifo_lock_release(&ufifo->lock);
    return 0;

err4:
    close(ufifo->shm_fd);
    shm_unlink(ufifo->name);
err3:
    __ufifo_lock_release(&ufifo->lock);
err2:
    __ufifo_lock_deinit(&ufifo->lock);
err1:
    free(ufifo);
    return ret;
}

static int __ufifo_close(ufifo_t *handle, int destroy)
{
    int ret;

    ret = __ufifo_lock_acquire(&handle->lock);
    if (ret < 0) {
        return ret;
    }

    if (destroy) {
        __ufifo_bsem_deinit(handle->bsem_wr);
        __ufifo_bsem_deinit(handle->bsem_rd);
    }
    munmap(handle->shm_mem, handle->shm_size + (sizeof(kfifo_t) + 2 * sizeof(sem_t)));
    close(handle->shm_fd);

    __ufifo_lock_release(&handle->lock);
    if (destroy) {
        __ufifo_lock_deinit(&handle->lock);
        shm_unlink(handle->name);
    }
    free(handle);
    return 0;
}

int ufifo_close(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_close(handle, 0);
}

int ufifo_destroy(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_close(handle, 1);
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
            handle->shm_mem + offset,
            handle->kfifo->mask - offset + 1,
            handle->shm_mem);
    }

    return len;
}

static unsigned int __ufifo_peek_tag(ufifo_t *handle, unsigned int offset)
{
    unsigned int ret = 0;

    if (handle->hook.rectag) {
        offset &= handle->kfifo->mask;
        ret = handle->hook.rectag(
            handle->shm_mem + offset,
            handle->kfifo->mask - offset + 1,
            handle->shm_mem);
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

    __ufifo_lock_acquire(&handle->lock);
    handle->kfifo->out = handle->kfifo->in = 0;
    __ufifo_lock_release(&handle->lock);
}

unsigned int ufifo_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(&handle->lock);
    len = handle->kfifo->in - handle->kfifo->out;
    __ufifo_lock_release(&handle->lock);

    return len;
}

void ufifo_skip(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(&handle->lock);
    handle->kfifo->out += __ufifo_peek_len(handle, handle->kfifo->out);
    __ufifo_lock_release(&handle->lock);
}

unsigned int ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(&handle->lock);
    len = __ufifo_peek_len(handle, handle->kfifo->out);
    __ufifo_lock_release(&handle->lock);

    return len;
}

static unsigned int __ufifo_put(ufifo_t *handle, void *buf, unsigned int size, int block)
{
    int ret;
    unsigned int len;

    __ufifo_lock_acquire(&handle->lock);
    while (1) {
        len = __ufifo_unused_len(handle);
        if (len < size) {
            ret = block ? __ufifo_bsem_wait(handle->bsem_wr, &handle->lock) : 1;
            if (ret) {
                len = 0;
                goto end;
            }
        } else {
            break;
        }
    }
    if (handle->hook.recput) {
        len = handle->kfifo->mask & handle->kfifo->in;
        len = handle->hook.recput(
            handle->shm_mem + len,
            handle->kfifo->mask - len + 1,
            handle->shm_mem, buf);
        assert(size == len);
        handle->kfifo->in += len;
    } else {
        len = kfifo_in(handle->kfifo, handle->shm_mem, buf, size);
    }
    __ufifo_bsem_post(handle->bsem_rd);
end:
    __ufifo_lock_release(&handle->lock);

    return len;
}

unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_put(handle, buf, size, 0);
}

unsigned int ufifo_put_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_put(handle, buf, size, 1);
}

static unsigned int __ufifo_get(ufifo_t *handle, void *buf, unsigned int size, int block)
{
    int ret;
    unsigned int len;

    __ufifo_lock_acquire(&handle->lock);
    while (1) {
        len = __ufifo_peek_len(handle, handle->kfifo->out);
        if (len == 0) {
            ret = block ? __ufifo_bsem_wait(handle->bsem_rd, &handle->lock) : 1;
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }

    if (handle->hook.recget) {
        len = handle->kfifo->mask & handle->kfifo->out;
        len = handle->hook.recget(
            handle->shm_mem + len,
            handle->kfifo->mask - len + 1,
            handle->shm_mem, buf);
        handle->kfifo->out += len;
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out(handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_bsem_post(handle->bsem_wr);
end:
    __ufifo_lock_release(&handle->lock);

    return len;
}

unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get(handle, buf, size, 0);
}

unsigned int ufifo_get_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get(handle, buf, size, 1);
}

unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(&handle->lock);
    len = __ufifo_peek_len(handle, handle->kfifo->out);
    if (len == 0) {
        goto end;
    }
    size = handle->hook.recsize ? min(size, len) : size;
    len = kfifo_out_peek(handle->kfifo, handle->shm_mem, buf, size);
end:
    __ufifo_lock_release(&handle->lock);

    return len;
}

int ufifo_oldest(ufifo_t *handle, unsigned int tag)
{
    int ret;
    unsigned int len, tmp;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(&handle->lock);
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
    __ufifo_lock_release(&handle->lock);

    return ret;
}

int ufifo_newest(ufifo_t *handle, unsigned int tag)
{
    int ret;
    unsigned int len, tmp;
    unsigned int final = 0;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(&handle->lock);
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
    __ufifo_lock_release(&handle->lock);

    return ret;
}
