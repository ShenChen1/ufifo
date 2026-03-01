#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "kfifo.h"
#include "log2.h"
#include "ufifo.h"
#include "utils.h"

#define UFIFO_DEBUG (0)
#define UFIFO_MAGIC (0xf1f0f1f0)

#if UFIFO_DEBUG
#define UFIFO_CHECK_HANDLE_FUNC(handle) \
    assert((handle));                   \
    assert((handle)->magic == UFIFO_MAGIC);
#else
#define UFIFO_CHECK_HANDLE_FUNC(handle)
#endif

typedef struct {
    unsigned int out;
    pid_t pid;
    unsigned int active;
    sem_t bsem_rd;
} ufifo_sub_ctrl_t;

typedef struct {
    unsigned int in;
    unsigned int out;
    unsigned int mask;

    ufifo_lock_e lock;
    pthread_mutex_t mutex;

    sem_t bsem_wr;
    sem_t bsem_rd;

    ufifo_data_mode_e data_mode;
    unsigned int max_users;
    unsigned int num_users;
    ufifo_sub_ctrl_t users[];
} ufifo_ctrl_t;

struct ufifo {
#if UFIFO_DEBUG
    unsigned int magic;
#endif
    char name[NAME_MAX];
    unsigned int user_id;

    ufifo_hook_t hook;
    kfifo_t kfifo;
    sem_t *bsem_wr;
    sem_t *bsem_rd;

    int shm_fd;
    unsigned int shm_size;
    void *shm_mem;

    int ctrl_fd;
    size_t ctrl_size;
    ufifo_ctrl_t *ctrl;

    int efd; /* UDS notification socket for epoll, -1 if unused */
};

/* Process-global sender socket for UDS notifications (lazy init) */
static int __ufifo_sender_fd = -1;
static pthread_once_t __ufifo_sender_once = PTHREAD_ONCE_INIT;

static void __ufifo_sender_init(void)
{
    __ufifo_sender_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

static int __ufifo_get_sender_fd(void)
{
    pthread_once(&__ufifo_sender_once, __ufifo_sender_init);
    return __ufifo_sender_fd;
}

/* Build abstract-namespace address: \0ufifo_<name>_<user_id> */
static socklen_t __ufifo_notify_addr(const char *name, unsigned int user_id, struct sockaddr_un *addr)
{
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    int n = snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "ufifo_%s_%u", name, user_id);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

/* Notify all active users of this FIFO via UDS sendto */
static void __ufifo_efd_notify(ufifo_t *handle)
{
    int sfd = __ufifo_get_sender_fd();
    if (sfd < 0)
        return;

    unsigned int i;
    struct sockaddr_un addr;
    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (!handle->ctrl->users[i].active)
            continue;
        socklen_t len = __ufifo_notify_addr(handle->name, i, &addr);
        sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, len);
    }
}

static inline int __ufifo_lock_acquire(ufifo_t *ufifo)
{
    int ret;

    if (ufifo->ctrl->lock == UFIFO_LOCK_NONE) {
        return 0;
    }

    ret = pthread_mutex_lock(&ufifo->ctrl->mutex);
    if (ret == EOWNERDEAD) {
        pthread_mutex_consistent(&ufifo->ctrl->mutex);
        ret = 0;
    }

    return ret;
}

static inline int __ufifo_lock_release(ufifo_t *ufifo)
{
    if (ufifo->ctrl->lock == UFIFO_LOCK_NONE) {
        return 0;
    }

    return pthread_mutex_unlock(&ufifo->ctrl->mutex);
}

static inline size_t __ufifo_ctrl_size(unsigned int max_users)
{
    return sizeof(ufifo_ctrl_t) + max_users * sizeof(ufifo_sub_ctrl_t);
}

static inline int __ufifo_is_shared(ufifo_t *ufifo)
{
    return ufifo->ctrl->data_mode == UFIFO_DATA_SHARED;
}

static int __ufifo_register(ufifo_t *ufifo)
{
    ufifo_ctrl_t *ctrl = ufifo->ctrl;
    unsigned int i;

    __ufifo_lock_acquire(ufifo);

    for (i = 0; i < ctrl->max_users; i++) {
        if (!ctrl->users[i].active) {
            ctrl->users[i].out = ctrl->in;
            ctrl->users[i].pid = getpid();
            ctrl->users[i].active = 1;
            ctrl->num_users++;
            __ufifo_lock_release(ufifo);
            return i;
        }
    }

    __ufifo_lock_release(ufifo);
    return -ENOSPC;
}

static void __ufifo_unregister(ufifo_t *ufifo)
{
    ufifo_ctrl_t *ctrl = ufifo->ctrl;

    __ufifo_lock_acquire(ufifo);

    if (ufifo->user_id < ctrl->max_users && ctrl->users[ufifo->user_id].active) {
        ctrl->users[ufifo->user_id].active = 0;
        ctrl->num_users--;
    }

    __ufifo_lock_release(ufifo);
}

static inline int __ufifo_lock_init(ufifo_t *ufifo, ufifo_lock_e type)
{
    pthread_mutexattr_t attr;
    int ret = 0;

    ufifo->ctrl->lock = type;
    if (type == UFIFO_LOCK_NONE) {
        return 0;
    }

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    ret = pthread_mutex_init(&ufifo->ctrl->mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    return ret;
}

static inline int __ufifo_lock_deinit(ufifo_t *ufifo)
{
    if (ufifo->ctrl->lock == UFIFO_LOCK_NONE) {
        return 0;
    }

    return pthread_mutex_destroy(&ufifo->ctrl->mutex);
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

    __ufifo_lock_release(ufifo);
    ret = sem_wait(bsem);
    __ufifo_lock_acquire(ufifo);

    return ret;
}

static int __ufifo_bsem_timedwait(sem_t *bsem, ufifo_t *ufifo, long millisec)
{
    int ret;
    struct timespec wt;
    struct timespec ts;

    __ufifo_lock_release(ufifo);

    wt.tv_sec = millisec / 1000;
    wt.tv_nsec = (millisec % 1000) * 1000000;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    wt.tv_sec += ts.tv_sec;
    wt.tv_nsec += ts.tv_nsec;
    if (wt.tv_nsec >= 1000000000) {
        wt.tv_sec += 1;
        wt.tv_nsec %= 1000000000;
    }

    ret = sem_clockwait(bsem, CLOCK_MONOTONIC, &wt);
    if (ret && errno == ETIMEDOUT) {
        ret = ETIMEDOUT;
    }

    __ufifo_lock_acquire(ufifo);

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
    struct stat st;
    char ctrl_name[NAME_MAX + 8];

    snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", ufifo->name);
    ufifo->ctrl_fd = shm_open(ctrl_name, O_RDWR, (S_IRUSR | S_IWUSR));
    if (ufifo->ctrl_fd < 0) {
        ret = -errno;
        goto end;
    }

    ret = fstat(ufifo->ctrl_fd, &st);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    ufifo->ctrl_size = st.st_size;
    ufifo->ctrl = mmap(NULL, ufifo->ctrl_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->ctrl_fd, 0);
    if (ufifo->ctrl == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    ret = fstat(ufifo->shm_fd, &st);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    ufifo->shm_size = st.st_size;
    ufifo->shm_mem = mmap(NULL, ufifo->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->shm_fd, 0);
    if (ufifo->shm_mem == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    ufifo->kfifo.in = &ufifo->ctrl->in;
    ufifo->kfifo.out = &ufifo->ctrl->out;
    ufifo->kfifo.mask = &ufifo->ctrl->mask;
    ufifo->bsem_wr = &ufifo->ctrl->bsem_wr;
    ufifo->bsem_rd = &ufifo->ctrl->bsem_rd;

    return 0;

err_ctrl_mmap:
    munmap(ufifo->ctrl, ufifo->ctrl_size);
err_ctrl_fd:
    close(ufifo->ctrl_fd);
end:
    return ret;
}

static int __ufifo_init_from_user(ufifo_t *ufifo, ufifo_alloc_t *alloc)
{
    int ret = 0;
    unsigned int i;
    char ctrl_name[NAME_MAX + 8];

    if (!alloc->size) {
        return -EINVAL;
    }

    snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", ufifo->name);
    ufifo->ctrl_size = __ufifo_ctrl_size(alloc->max_users);
    ufifo->ctrl_fd = shm_open(ctrl_name, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR));
    if (ufifo->ctrl_fd < 0) {
        ret = -errno;
        goto end;
    }

    ret = ftruncate(ufifo->ctrl_fd, ufifo->ctrl_size);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    ufifo->ctrl = mmap(NULL, ufifo->ctrl_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->ctrl_fd, 0);
    if (ufifo->ctrl == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    ufifo->shm_size = roundup_pow_of_two(alloc->size);
    ret = ftruncate(ufifo->shm_fd, ufifo->shm_size);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    ufifo->shm_mem = mmap(NULL, ufifo->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->shm_fd, 0);
    if (ufifo->shm_mem == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    ufifo->ctrl->data_mode = alloc->data_mode;
    ufifo->ctrl->max_users = alloc->max_users;
    ufifo->ctrl->num_users = 0;
    for (i = 0; i < alloc->max_users; i++) {
        ufifo->ctrl->users[i].active = 0;
    }

    ufifo->kfifo.in = &ufifo->ctrl->in;
    ufifo->kfifo.out = &ufifo->ctrl->out;
    ufifo->kfifo.mask = &ufifo->ctrl->mask;
    ret |= kfifo_init(&ufifo->kfifo, ufifo->shm_size);
    ufifo->bsem_wr = &ufifo->ctrl->bsem_wr;
    ret |= __ufifo_bsem_init(ufifo->bsem_wr, 0);
    ufifo->bsem_rd = &ufifo->ctrl->bsem_rd;
    ret |= __ufifo_bsem_init(ufifo->bsem_rd, 0);

    return ret;

err_ctrl_mmap:
    munmap(ufifo->ctrl, ufifo->ctrl_size);
err_ctrl_fd:
    close(ufifo->ctrl_fd);
    shm_unlink(ctrl_name);
end:
    return ret;
}

static int __ufifo_init_validate(const ufifo_init_t *init)
{
    if (init->opt >= UFIFO_OPT_MAX) {
        return -EINVAL;
    }

    if (init->opt == UFIFO_OPT_ALLOC) {
        if (init->alloc.max_users < 1) {
            return -EINVAL;
        }
        if (init->alloc.lock >= UFIFO_LOCK_MAX) {
            return -EINVAL;
        }
        if (init->alloc.data_mode >= UFIFO_DATA_MAX) {
            return -EINVAL;
        }
    }

    return 0;
}

int ufifo_open(char *name, ufifo_init_t *init, ufifo_t **handle)
{
    int ret = 0;
    ufifo_t *ufifo = NULL;
    int is_alloc = 0;

    if (name == NULL || init == NULL || handle == NULL) {
        return -EINVAL;
    }

    ret = __ufifo_init_validate(init);
    if (ret < 0) {
        return ret;
    }

    ufifo = calloc(1, sizeof(ufifo_t));
    if (ufifo == NULL) {
        return -ENOMEM;
    }
    ufifo->efd = -1;

    strncpy(ufifo->name, name, sizeof(ufifo->name) - 1);
    ret |= __ufifo_hook_init(ufifo, &init->hook);
    if (ret < 0) {
        goto err1;
    }

    int oflag = O_RDWR;
    if (init->opt == UFIFO_OPT_ALLOC) {
        ufifo->shm_fd = shm_open(name, oflag, (S_IRUSR | S_IWUSR));
        if (ufifo->shm_fd >= 0 && init->alloc.force == 0) {
            init->opt = UFIFO_OPT_ATTACH;
        } else {
            oflag = O_RDWR | O_CREAT;
        }
        if (ufifo->shm_fd >= 0) {
            close(ufifo->shm_fd);
        }
    }

    ufifo->shm_fd = shm_open(name, oflag, (S_IRUSR | S_IWUSR));
    if (ufifo->shm_fd < 0) {
        ret = -errno;
        goto err1;
    }

    is_alloc = (init->opt == UFIFO_OPT_ALLOC);
    if (is_alloc) {
        ret = __ufifo_init_from_user(ufifo, &init->alloc);
        if (ret < 0) {
            goto err2;
        }
        ret = __ufifo_lock_init(ufifo, init->alloc.lock);
        if (ret < 0) {
            goto err3;
        }
    } else {
        ret = __ufifo_init_from_shm(ufifo);
        if (ret < 0) {
            goto err2;
        }
    }

    ret = __ufifo_register(ufifo);
    if (ret < 0) {
        goto err4;
    }
    if (__ufifo_is_shared(ufifo)) {
        ufifo->user_id = (unsigned int)ret;
        __ufifo_bsem_deinit(ufifo->bsem_rd);
        ufifo->bsem_rd = &ufifo->ctrl->users[ufifo->user_id].bsem_rd;
        ret |= __ufifo_bsem_init(ufifo->bsem_rd, 0);
        ufifo->kfifo.out = &ufifo->ctrl->users[ufifo->user_id].out;
    }

#if UFIFO_DEBUG
    ufifo->magic = UFIFO_MAGIC;
#endif
    *handle = ufifo;
    return 0;

err4:
    if (is_alloc) {
        __ufifo_lock_deinit(ufifo);
    }
err3:
    __ufifo_bsem_deinit(ufifo->bsem_wr);
    __ufifo_bsem_deinit(ufifo->bsem_rd);
    munmap(ufifo->shm_mem, ufifo->shm_size);
    munmap(ufifo->ctrl, ufifo->ctrl_size);
    close(ufifo->ctrl_fd);
    if (is_alloc) {
        char ctrl_name[NAME_MAX + 8];
        snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", ufifo->name);
        shm_unlink(ctrl_name);
    }
err2:
    close(ufifo->shm_fd);
    if (is_alloc) {
        shm_unlink(ufifo->name);
    }
err1:
    free(ufifo);
    return ret;
}

static int __ufifo_close(ufifo_t *handle, int destroy)
{
    char ctrl_name[NAME_MAX + 8];

    if (handle->efd >= 0) {
        close(handle->efd);
        handle->efd = -1;
    }
    __ufifo_unregister(handle);
    if (destroy) {
        unsigned int i;
        __ufifo_lock_deinit(handle);
        __ufifo_bsem_deinit(handle->bsem_wr);
        for (i = 0; i < handle->ctrl->max_users; i++) {
            __ufifo_bsem_deinit(&handle->ctrl->users[i].bsem_rd);
        }
    }

    munmap(handle->shm_mem, handle->shm_size);
    close(handle->shm_fd);

    munmap(handle->ctrl, handle->ctrl_size);
    close(handle->ctrl_fd);

    if (destroy) {
        shm_unlink(handle->name);
        snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", handle->name);
        shm_unlink(ctrl_name);
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

/*
 * Return the out pointer of the slowest (furthest-behind) active consumer.
 * In SHARED mode, producers must not write past this point.
 */
static unsigned int __ufifo_min_out(ufifo_t *handle)
{
    unsigned int in_val = *handle->kfifo.in;
    unsigned int max_distance = 0;
    unsigned int min_out = in_val;
    unsigned int i;

    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (handle->ctrl->users[i].active) {
            unsigned int distance = in_val - handle->ctrl->users[i].out;
            if (distance > max_distance) {
                max_distance = distance;
                min_out = handle->ctrl->users[i].out;
            }
        }
    }

    return min_out;
}

static unsigned int __ufifo_unused_len(ufifo_t *handle)
{
    unsigned int out;
    unsigned int len;

    if (__ufifo_is_shared(handle)) {
        out = __ufifo_min_out(handle);
    } else {
        out = *handle->kfifo.out;
    }

    len = *handle->kfifo.in - out;
    return *handle->kfifo.mask + 1 - len;
}

static unsigned int __ufifo_peek_len(ufifo_t *handle, unsigned int offset)
{
    unsigned int len = *handle->kfifo.in == offset ? 0 : 1;

    if (len && handle->hook.recsize) {
        offset &= *handle->kfifo.mask;
        len = handle->hook.recsize(handle->shm_mem + offset, *handle->kfifo.mask - offset + 1, handle->shm_mem);
    }

    return len;
}

static unsigned int __ufifo_peek_tag(ufifo_t *handle, unsigned int offset)
{
    unsigned int ret = 0;

    if (handle->hook.rectag) {
        offset &= *handle->kfifo.mask;
        ret = handle->hook.rectag(handle->shm_mem + offset, *handle->kfifo.mask - offset + 1, handle->shm_mem);
    }

    return ret;
}

unsigned int ufifo_size(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return *handle->kfifo.mask + 1;
}

void ufifo_reset(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    *handle->kfifo.out = *handle->kfifo.in = 0;
    __ufifo_lock_release(handle);
}

unsigned int ufifo_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    len = *handle->kfifo.in - *handle->kfifo.out;
    __ufifo_lock_release(handle);

    return len;
}

void ufifo_skip(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    *handle->kfifo.out += __ufifo_peek_len(handle, *handle->kfifo.out);
    __ufifo_lock_release(handle);
}

unsigned int ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    len = __ufifo_peek_len(handle, *handle->kfifo.out);
    __ufifo_lock_release(handle);

    return len;
}

static unsigned int __ufifo_put(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;

    __ufifo_lock_acquire(handle);
    while (1) {
        len = __ufifo_unused_len(handle);
        if (len < size) {
            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_bsem_wait(handle->bsem_wr, handle);
            } else {
                ret = __ufifo_bsem_timedwait(handle->bsem_wr, handle, millisec);
                millisec = 0;
            }
            if (ret) {
                len = 0;
                goto end;
            }
        } else {
            break;
        }
    }
    if (handle->hook.recput) {
        len = *handle->kfifo.mask & *handle->kfifo.in;
        len = handle->hook.recput(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        assert(size == len);
        smp_wmb();
        *handle->kfifo.in += len;
    } else {
        len = kfifo_in(&handle->kfifo, handle->shm_mem, buf, size);
    }

    if (__ufifo_is_shared(handle)) {
        unsigned int i;
        for (i = 0; i < handle->ctrl->max_users; i++) {
            if (handle->ctrl->users[i].active) {
                __ufifo_bsem_post(&handle->ctrl->users[i].bsem_rd);
            }
        }
    } else {
        __ufifo_bsem_post(handle->bsem_rd);
    }
    __ufifo_efd_notify(handle);

end:
    __ufifo_lock_release(handle);

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
    return __ufifo_put(handle, buf, size, -1);
}

unsigned int ufifo_put_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_put(handle, buf, size, millisec);
}

static unsigned int __ufifo_get(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;

    __ufifo_lock_acquire(handle);
    while (1) {
        len = __ufifo_peek_len(handle, *handle->kfifo.out);
        if (len == 0) {
            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_bsem_wait(handle->bsem_rd, handle);
            } else {
                ret = __ufifo_bsem_timedwait(handle->bsem_rd, handle, millisec);
                millisec = 0;
            }
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }

    if (handle->hook.recget) {
        len = *handle->kfifo.mask & *handle->kfifo.out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        smp_wmb();
        *handle->kfifo.out += len;
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_bsem_post(handle->bsem_wr);
    __ufifo_efd_notify(handle);

end:
    __ufifo_lock_release(handle);

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
    return __ufifo_get(handle, buf, size, -1);
}

unsigned int ufifo_get_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get(handle, buf, size, millisec);
}

static unsigned int __ufifo_peek(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;

    __ufifo_lock_acquire(handle);
    while (1) {
        len = __ufifo_peek_len(handle, *handle->kfifo.out);
        if (len == 0) {
            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_bsem_wait(handle->bsem_rd, handle);
            } else {
                ret = __ufifo_bsem_timedwait(handle->bsem_rd, handle, millisec);
                millisec = 0;
            }
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }

    if (handle->hook.recget) {
        len = *handle->kfifo.mask & *handle->kfifo.out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        smp_wmb();
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out_peek(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_bsem_post(handle->bsem_wr);
end:
    __ufifo_lock_release(handle);

    return len;
}

unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_peek(handle, buf, size, 0);
}

unsigned int ufifo_peek_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_peek(handle, buf, size, -1);
}

unsigned int ufifo_peek_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_peek(handle, buf, size, millisec);
}

int ufifo_oldest(ufifo_t *handle, unsigned int tag)
{
    int ret = 0;
    unsigned int len, tmp;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    tmp = *handle->kfifo.out;
    while (1) {
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
    *handle->kfifo.out = tmp;
    __ufifo_lock_release(handle);

    return ret;
}

int ufifo_newest(ufifo_t *handle, unsigned int tag)
{
    int ret = 0;
    bool found = false;
    unsigned int len, tmp;
    unsigned int final = 0;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_lock_acquire(handle);
    tmp = *handle->kfifo.out;
    while (1) {
        len = __ufifo_peek_len(handle, tmp);
        if (!len) {
            tmp = found ? final : tmp;
            ret = found ? 0 : -ESPIPE;
            break;
        }
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            found = true;
            final = tmp;
        }
        tmp += len;
    }
    *handle->kfifo.out = tmp;
    __ufifo_lock_release(handle);

    return ret;
}

int ufifo_get_fd(ufifo_t *handle)
{
    struct sockaddr_un addr;
    socklen_t addr_len;

    UFIFO_CHECK_HANDLE_FUNC(handle);

    if (handle->efd >= 0)
        return handle->efd;

    handle->efd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (handle->efd < 0)
        return -1;

    addr_len = __ufifo_notify_addr(handle->name, handle->user_id, &addr);
    if (bind(handle->efd, (struct sockaddr *)&addr, addr_len) < 0) {
        close(handle->efd);
        handle->efd = -1;
        return -1;
    }

    /* Pre-arm: if FIFO already has data, send notification to self */
    if (*handle->kfifo.in != *handle->kfifo.out) {
        int sfd = __ufifo_get_sender_fd();
        if (sfd >= 0)
            sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, addr_len);
    }

    return handle->efd;
}
