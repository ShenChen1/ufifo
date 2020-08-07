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
#include "kfifo.h"
#include "ufifo.h"

#define UFIFO_MAGIC (0xf1f0f1f0)

struct ufifo {
    unsigned int    magic;

    char            name[NAME_MAX];
    fdlock_t       *lock;

    int             shm_fd;
    unsigned int    shm_size;
    void           *shm_mem;

    struct __kfifo *kfifo;
};

static inline int ufifo_fdlock_acquire(ufifo_t *ufifo)
{
    char path[NAME_MAX];
    snprintf(path, sizeof(path), "/var/lock/%s.lock", ufifo->name);
    return fdlock_acquire(path, &ufifo->lock);
}

static inline int ufifo_fdlock_release(ufifo_t *ufifo)
{
    return fdlock_release(&ufifo->lock);
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
    ret = kfifo_init(ufifo->kfifo, ufifo->shm_mem, ufifo->shm_size, 1);

end:
    return ret;
}

int ufifo_open(char *name, ufifo_opt_e opt, unsigned int size, ufifo_t **handle)
{
    int ret = 0;
    ufifo_t *ufifo = NULL;

    if (name == NULL || opt >= UFIFO_OPT_NONE) {
        return -EINVAL;
    }

    ufifo = malloc(sizeof(ufifo_t));
    if (ufifo == NULL) {
        return -ENOMEM;
    }

    strncpy(ufifo->name, name, sizeof(ufifo->name));
    ret = ufifo_fdlock_acquire(ufifo);
    if (ret < 0) {
        goto err1;
    }

    int oflag = (opt == UFIFO_OPT_ALLOC) ? (O_RDWR | O_CREAT) : (O_RDWR);
    ufifo->shm_fd = shm_open(name, oflag, (S_IRUSR | S_IWUSR));
    if (ufifo->shm_fd < 0) {
        ret = -errno;
        goto err2;
    }

    ufifo->shm_size = size;
    ret = (opt == UFIFO_OPT_ALLOC) ? ufifo_init_from_user(ufifo) : ufifo_init_from_shm(ufifo);
    if (ret < 0) {
        goto err3;
    }

    *handle = ufifo;
    ufifo_fdlock_release(ufifo);
    return 0;

err3:
    close(ufifo->shm_fd);
    shm_unlink(ufifo->name);
err2:
    ufifo_fdlock_release(ufifo);
err1:
    free(ufifo);
    return ret;
}

int ufifo_close(ufifo_t *handle)
{
    int ret;
    ufifo_t *ufifo = handle;

    ret = ufifo_fdlock_acquire(ufifo);
    if (ret < 0) {
        return ret;
    }

    munmap(ufifo->shm_mem, ufifo->shm_size);
    close(ufifo->shm_fd);

    ufifo_fdlock_release(ufifo);
    free(ufifo);

    return 0;
}

unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size)
{
    ufifo_t *ufifo = handle;

    ufifo_fdlock_acquire(ufifo);
    unsigned int ret = kfifo_in(ufifo->kfifo, buf, size);
    ufifo_fdlock_release(ufifo);

    return ret;
}

unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size)
{
    ufifo_t *ufifo = handle;

    ufifo_fdlock_acquire(ufifo);
    unsigned int ret = kfifo_out(ufifo->kfifo, buf, size);
    ufifo_fdlock_release(ufifo);

    return ret;
}

unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size)
{
    ufifo_t *ufifo = handle;

    ufifo_fdlock_acquire(ufifo);
    unsigned int ret = kfifo_out_peek(ufifo->kfifo, buf, size);
    ufifo_fdlock_release(ufifo);

    return ret;
}

unsigned int ufifo_len(ufifo_t *handle)
{
    ufifo_t *ufifo = handle;

    ufifo_fdlock_acquire(ufifo);
    unsigned int ret = kfifo_len(ufifo->kfifo);
    ufifo_fdlock_release(ufifo);

    return ret;
}

void ufifo_skip(ufifo_t *handle)
{
    ufifo_t *ufifo = handle;

    ufifo_fdlock_acquire(ufifo);
    ufifo->kfifo->out++;
    ufifo_fdlock_release(ufifo);
}