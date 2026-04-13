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

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_CHECK_HANDLE_FUNC(handle) \
    assert((handle));                   \
    assert((handle)->magic == UFIFO_MAGIC);

/* epoll notification state machine: IDLE → REGISTERED → PENDING → REGISTERED */
enum {
    UFIFO_EFD_IDLE = 0,       /* no epoll fd registered */
    UFIFO_EFD_REGISTERED = 1, /* epoll fd registered, no pending notification */
    UFIFO_EFD_PENDING = 2,    /* epoll fd registered, notification sent but not yet drained */
};

typedef struct {
    pid_t pid;
    unsigned int active;

    unsigned int out;
    sem_t bsem_rd;
    int efd_rx_flag; /* per-user RX epoll state (IDLE/REGISTERED/PENDING) */
} ufifo_sub_ctrl_t;

typedef struct {
    ufifo_version_t ver;

    unsigned int in;
    unsigned int mask;

    ufifo_lock_e lock;
    pthread_mutex_t ctrl_mutex; /* always active: protects control data */
    pthread_mutex_t data_mutex; /* governed by ufifo_lock_e: protects index movement */

    sem_t bsem_wr;
    int efd_tx_flag; /* global TX epoll state (IDLE/REGISTERED/PENDING) */

    ufifo_data_mode_e data_mode;
    unsigned int max_users;
    unsigned int num_users;
    ufifo_sub_ctrl_t users[];
} ufifo_ctrl_t;

struct ufifo {
    unsigned int magic;

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

    int rx_efd;
    int tx_efd;
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

/* Build abstract-namespace address */
static socklen_t __ufifo_notify_addr(const char *name, unsigned int user_id, struct sockaddr_un *addr, int is_rx)
{
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    int n =
        snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "ufifo_%s_%s_%u", is_rx ? "rx" : "tx", name, user_id);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

/*
 * Notify consumers that data is available (called after put).
 * Skips users without epoll fd registered; coalesces if already pending.
 */
static void __ufifo_efd_notify_rx(ufifo_t *handle)
{
    int sfd = __ufifo_get_sender_fd();
    if (sfd < 0)
        return;

    unsigned int i;
    struct sockaddr_un addr;
    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (!READ_ONCE(&handle->ctrl->users[i].active))
            continue;

        unsigned int state = smp_load_acquire(&handle->ctrl->users[i].efd_rx_flag);
        if (state != UFIFO_EFD_REGISTERED)
            continue; /* IDLE → skip; PENDING → coalesce */

        smp_store_release(&handle->ctrl->users[i].efd_rx_flag, UFIFO_EFD_PENDING);
        socklen_t len = __ufifo_notify_addr(handle->name, i, &addr, 1);
        sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, len);
    }
}

/*
 * Notify producers that space is available (called after get).
 * TX flag is global in ufifo_ctrl_t (like bsem_wr).
 */
static void __ufifo_efd_notify_tx(ufifo_t *handle)
{
    int state = smp_load_acquire(&handle->ctrl->efd_tx_flag);
    if (state != UFIFO_EFD_REGISTERED)
        return; /* IDLE → no one registered; PENDING → coalesce */

    smp_store_release(&handle->ctrl->efd_tx_flag, UFIFO_EFD_PENDING);

    int sfd = __ufifo_get_sender_fd();
    if (sfd < 0)
        return;

    unsigned int i;
    struct sockaddr_un addr;
    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (!READ_ONCE(&handle->ctrl->users[i].active))
            continue;
        socklen_t len = __ufifo_notify_addr(handle->name, i, &addr, 0);
        sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, len);
    }
}

/* Control-plane lock: always active, protects register/unregister/efd/dump */
static inline int __ufifo_ctrl_lock(ufifo_t *ufifo)
{
    int ret = pthread_mutex_lock(&ufifo->ctrl->ctrl_mutex);
    if (ret == EOWNERDEAD) {
        pthread_mutex_consistent(&ufifo->ctrl->ctrl_mutex);
        ret = 0;
    }
    return ret;
}

static inline int __ufifo_ctrl_unlock(ufifo_t *ufifo)
{
    return pthread_mutex_unlock(&ufifo->ctrl->ctrl_mutex);
}

/* Data-plane lock: governed by ufifo_lock_e, protects index movement */
static inline int __ufifo_data_lock(ufifo_t *ufifo)
{
    if (ufifo->ctrl->lock == UFIFO_LOCK_NONE)
        return 0;

    int ret = pthread_mutex_lock(&ufifo->ctrl->data_mutex);
    if (ret == EOWNERDEAD) {
        pthread_mutex_consistent(&ufifo->ctrl->data_mutex);
        ret = 0;
    }
    return ret;
}

static inline int __ufifo_data_unlock(ufifo_t *ufifo)
{
    if (ufifo->ctrl->lock == UFIFO_LOCK_NONE)
        return 0;

    return pthread_mutex_unlock(&ufifo->ctrl->data_mutex);
}

static inline size_t __ufifo_ctrl_size(unsigned int max_users)
{
    return sizeof(ufifo_ctrl_t) + max_users * sizeof(ufifo_sub_ctrl_t);
}

static inline int __ufifo_is_shared(ufifo_t *ufifo)
{
    return ufifo->ctrl->data_mode == UFIFO_DATA_SHARED;
}

/* Forward declarations for bsem helpers used in __ufifo_register slow path */
static int __ufifo_bsem_init(sem_t *bsem, unsigned int value);
static int __ufifo_bsem_deinit(sem_t *bsem);

/* OFD (Open File Description) lock helpers for process liveness detection.
 * Each user slot claims byte range [user_id, user_id+1) on the ctrl shm fd.
 * Kernel auto-releases when the fd's open file description is closed. */

static int __ufifo_ofd_lock(int fd, unsigned int user_id)
{
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

static int __ufifo_ofd_unlock(int fd, unsigned int user_id)
{
    struct flock fl = { .l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

/*
 * Probe whether user slot belongs to a dead process.
 * Uses F_OFD_GETLK to query the lock status (zero side-effects).
 * Returns: 1 = dead (byte range unlocked), 0 = alive or inconclusive.
 */
static int __ufifo_is_user_dead(int fd, unsigned int user_id)
{
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    if (fcntl(fd, F_OFD_GETLK, &fl) < 0)
        return 0;                /* cannot query, be conservative */
    return fl.l_type == F_UNLCK; /* unlocked = holder is dead */
}

/*
 * Reap a dead user slot.
 * Assumes the caller holds ctrl_mutex.
 */
static void __ufifo_reap_dead_user(ufifo_ctrl_t *ctrl, unsigned int user_id)
{
    if (READ_ONCE(&ctrl->users[user_id].active)) {
        WRITE_ONCE(&ctrl->users[user_id].active, 0);
        ctrl->num_users--;

        /* Drain the semaphore instead of destroying it to avoid races */
        while (sem_trywait(&ctrl->users[user_id].bsem_rd) == 0) {
            /* do nothing, just decrementing to 0 */
        }
    }
}

static int __ufifo_register(ufifo_t *ufifo)
{
    ufifo_ctrl_t *ctrl = ufifo->ctrl;
    unsigned int i;
    pid_t mypid = getpid();

    for (i = 0; i < ctrl->max_users; i++) {
        if (!READ_ONCE(&ctrl->users[i].active)) {
            WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(ufifo->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, 1);
            ctrl->num_users++;
            return i;
        }
    }

    /* Slow path: no slots available. Try to reap dead processes. */
    for (i = 0; i < ctrl->max_users; i++) {
        if (READ_ONCE(&ctrl->users[i].active) && __ufifo_is_user_dead(ufifo->ctrl_fd, i)) {
            __ufifo_reap_dead_user(ctrl, i);

            WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(ufifo->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, 1);
            ctrl->num_users++;
            return i;
        }
    }

    return -ENOSPC;
}

static void __ufifo_unregister(ufifo_t *ufifo)
{
    ufifo_ctrl_t *ctrl = ufifo->ctrl;

    if (ufifo->user_id < ctrl->max_users && READ_ONCE(&ctrl->users[ufifo->user_id].active)) {
        smp_store_release(&ctrl->users[ufifo->user_id].active, 0);
        __ufifo_ofd_unlock(ufifo->ctrl_fd, ufifo->user_id);
        ctrl->num_users--;
    }
}

static inline int __ufifo_lock_init(ufifo_t *ufifo, ufifo_lock_e type)
{
    pthread_mutexattr_t attr;
    int ret = 0;

    ufifo->ctrl->lock = type;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);

    /* ctrl_mutex: always initialized */
    ret = pthread_mutex_init(&ufifo->ctrl->ctrl_mutex, &attr);

    /* data_mutex: only when locking is requested */
    if (ret == 0 && type != UFIFO_LOCK_NONE) {
        ret = pthread_mutex_init(&ufifo->ctrl->data_mutex, &attr);
    }

    pthread_mutexattr_destroy(&attr);
    return ret;
}

static inline int __ufifo_lock_deinit(ufifo_t *ufifo)
{
    int ret = pthread_mutex_destroy(&ufifo->ctrl->ctrl_mutex);

    if (ufifo->ctrl->lock != UFIFO_LOCK_NONE) {
        ret |= pthread_mutex_destroy(&ufifo->ctrl->data_mutex);
    }

    return ret;
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

    __ufifo_data_unlock(ufifo);
    ret = sem_wait(bsem);
    __ufifo_data_lock(ufifo);

    return ret;
}

static int __ufifo_bsem_timedwait(sem_t *bsem, ufifo_t *ufifo, long millisec)
{
    int ret;
    struct timespec wt;
    struct timespec ts;

    __ufifo_data_unlock(ufifo);

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

    __ufifo_data_lock(ufifo);

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

static int __ufifo_version_check(ufifo_ctrl_t *ctrl)
{
    ufifo_version_t ver = {};
    ufifo_get_version_info(NULL, &ver);

    if (ctrl->ver.major != ver.major) {
        fprintf(stderr,
                "ufifo: version mismatch (shm=%u.%u.%u, lib=%u.%u.%u)\n",
                ctrl->ver.major,
                ctrl->ver.minor,
                ctrl->ver.patch,
                ver.major,
                ver.minor,
                ver.patch);
        return -EPROTO;
    }
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

    /* Validate version compatibility before accessing other ctrl fields */
    ret = __ufifo_version_check(ufifo->ctrl);
    if (ret < 0) {
        goto err_ctrl_mmap;
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

    __ufifo_ctrl_lock(ufifo);
    ret = __ufifo_register(ufifo);
    __ufifo_ctrl_unlock(ufifo);
    if (ret < 0) {
        goto err_ctrl_mmap;
    }
    ufifo->user_id = (unsigned int)ret;
    ufifo->kfifo.in = &ufifo->ctrl->in;
    ufifo->kfifo.mask = &ufifo->ctrl->mask;
    ufifo->bsem_wr = &ufifo->ctrl->bsem_wr;
    if (ufifo->ctrl->data_mode == UFIFO_DATA_SHARED) {
        ufifo->ctrl->users[ufifo->user_id].out = READ_ONCE(&ufifo->ctrl->in);
        ufifo->kfifo.out = &ufifo->ctrl->users[ufifo->user_id].out;
        ufifo->bsem_rd = &ufifo->ctrl->users[ufifo->user_id].bsem_rd;
    } else {
        ufifo->kfifo.out = &ufifo->ctrl->users[0].out;
        ufifo->bsem_rd = &ufifo->ctrl->users[0].bsem_rd;
    }

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
        __ufifo_bsem_init(&ufifo->ctrl->users[i].bsem_rd, 0);
    }

    ret = __ufifo_register(ufifo);
    if (ret < 0) {
        goto err_ctrl_mmap;
    }
    ufifo->user_id = (unsigned int)ret;
    ufifo_get_version_info(NULL, &ufifo->ctrl->ver);
    ufifo->kfifo.in = &ufifo->ctrl->in;
    ufifo->kfifo.out = &ufifo->ctrl->users[ufifo->user_id].out;
    ufifo->kfifo.mask = &ufifo->ctrl->mask;
    ret |= kfifo_init(&ufifo->kfifo, ufifo->shm_size);
    ufifo->bsem_wr = &ufifo->ctrl->bsem_wr;
    ret |= __ufifo_bsem_init(ufifo->bsem_wr, 0);
    ufifo->bsem_rd = &ufifo->ctrl->users[ufifo->user_id].bsem_rd;
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
    ufifo->rx_efd = -1;
    ufifo->tx_efd = -1;

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

    if (init->opt == UFIFO_OPT_ALLOC) {
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

    ufifo->magic = UFIFO_MAGIC;
    *handle = ufifo;
    return 0;

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

    if (handle->rx_efd >= 0) {
        smp_store_release(&handle->ctrl->users[handle->user_id].efd_rx_flag, UFIFO_EFD_IDLE);
        close(handle->rx_efd);
        handle->rx_efd = -1;
    }
    if (handle->tx_efd >= 0) {
        smp_store_release(&handle->ctrl->efd_tx_flag, UFIFO_EFD_IDLE);
        close(handle->tx_efd);
        handle->tx_efd = -1;
    }
    __ufifo_ctrl_lock(handle);
    __ufifo_unregister(handle);
    __ufifo_ctrl_unlock(handle);
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
    unsigned int in_val = READ_ONCE(handle->kfifo.in);
    unsigned int max_distance = 0;
    unsigned int min_out = in_val;
    unsigned int i;

    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (smp_load_acquire(&handle->ctrl->users[i].active)) {
            unsigned int u_out = smp_load_acquire(&handle->ctrl->users[i].out);
            unsigned int distance = in_val - u_out;
            if (distance > max_distance) {
                max_distance = distance;
                min_out = u_out;
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
        out = smp_load_acquire(handle->kfifo.out);
    }

    len = READ_ONCE(handle->kfifo.in) - out;
    return *handle->kfifo.mask + 1 - len;
}

static unsigned int __ufifo_peek_len(ufifo_t *handle, unsigned int offset)
{
    unsigned int len = smp_load_acquire(handle->kfifo.in) == offset ? 0 : 1;

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

    __ufifo_data_lock(handle);
    WRITE_ONCE(handle->kfifo.in, 0);
    WRITE_ONCE(handle->kfifo.out, 0);
    __ufifo_data_unlock(handle);
}

unsigned int ufifo_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    len = READ_ONCE(handle->kfifo.in) - READ_ONCE(handle->kfifo.out);
    __ufifo_data_unlock(handle);

    return len;
}

void ufifo_skip(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    unsigned int out = READ_ONCE(handle->kfifo.out);
    smp_store_release(handle->kfifo.out, out + __ufifo_peek_len(handle, out));
    __ufifo_data_unlock(handle);
}

unsigned int ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out));
    __ufifo_data_unlock(handle);

    return len;
}

static int __ufifo_try_reap_dead_readers(ufifo_t *handle)
{
    int cleaned = 0;
    unsigned int min_out = __ufifo_min_out(handle);
    unsigned int i;

    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (smp_load_acquire(&handle->ctrl->users[i].active)) {
            unsigned int u_out = smp_load_acquire(&handle->ctrl->users[i].out);
            /* Targeted check: Only check liveness if this user is the bottleneck */
            if (u_out == min_out && __ufifo_is_user_dead(handle->ctrl_fd, i)) {
                __ufifo_ctrl_lock(handle);
                if (READ_ONCE(&handle->ctrl->users[i].active)) {
                    __ufifo_reap_dead_user(handle->ctrl, i);
                    cleaned = 1;
                }
                __ufifo_ctrl_unlock(handle);
            }
        }
    }

    return cleaned;
}

static unsigned int __ufifo_put(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_unused_len(handle);
        if (len < size) {
            /* Slow path: Check if space is constrained by dead shared readers */
            if (__ufifo_is_shared(handle)) {
                if (__ufifo_try_reap_dead_readers(handle)) {
                    continue; /* Re-evaluate len */
                }
            }

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
        unsigned int in = READ_ONCE(handle->kfifo.in);
        len = *handle->kfifo.mask & in;
        len = handle->hook.recput(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        assert(size == len);
        smp_store_release(handle->kfifo.in, in + len);
    } else {
        len = kfifo_in(&handle->kfifo, handle->shm_mem, buf, size);
    }

    if (__ufifo_is_shared(handle)) {
        unsigned int i;
        for (i = 0; i < handle->ctrl->max_users; i++) {
            if (READ_ONCE(&handle->ctrl->users[i].active)) {
                __ufifo_bsem_post(&handle->ctrl->users[i].bsem_rd);
            }
        }
    } else {
        __ufifo_bsem_post(handle->bsem_rd);
    }
    __ufifo_efd_notify_rx(handle);

end:
    __ufifo_data_unlock(handle);

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

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out));
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
        unsigned int out = READ_ONCE(handle->kfifo.out);
        len = *handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        smp_store_release(handle->kfifo.out, out + len);
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_bsem_post(handle->bsem_wr);
    __ufifo_efd_notify_tx(handle);

end:
    __ufifo_data_unlock(handle);

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

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out));
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
        unsigned int out = READ_ONCE(handle->kfifo.out);
        len = *handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out_peek(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_bsem_post(handle->bsem_wr);
end:
    __ufifo_data_unlock(handle);

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

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
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
    smp_store_release(handle->kfifo.out, tmp);
    __ufifo_data_unlock(handle);

    return ret;
}

int ufifo_newest(ufifo_t *handle, unsigned int tag)
{
    int ret = 0;
    bool found = false;
    unsigned int len, tmp;
    unsigned int final = 0;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
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
    smp_store_release(handle->kfifo.out, tmp);
    __ufifo_data_unlock(handle);

    return ret;
}

static int __ufifo_get_efd(ufifo_t *handle, int is_rx)
{
    int ret_fd;
    __ufifo_ctrl_lock(handle);

    int *efd = is_rx ? &handle->rx_efd : &handle->tx_efd;
    int *efd_flags;
    struct sockaddr_un addr;
    socklen_t addr_len;

    if (*efd >= 0) {
        ret_fd = *efd;
        goto end;
    }

    *efd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (*efd < 0) {
        ret_fd = -1;
        goto end;
    }

    addr_len = __ufifo_notify_addr(handle->name, handle->user_id, &addr, is_rx);
    if (bind(*efd, (struct sockaddr *)&addr, addr_len) < 0) {
        close(*efd);
        *efd = -1;
        ret_fd = -1;
        goto end;
    }

    /* Mark this user as epoll-registered in shared memory */
    efd_flags = is_rx ? &handle->ctrl->users[handle->user_id].efd_rx_flag : &handle->ctrl->efd_tx_flag;
    smp_store_release(efd_flags, UFIFO_EFD_REGISTERED);

    /* Pre-arm condition: check if we should send a notification to self */
    int should_arm = 0;
    if (is_rx) {
        if (READ_ONCE(handle->kfifo.in) != READ_ONCE(handle->kfifo.out))
            should_arm = 1;
    } else {
        unsigned int len = READ_ONCE(handle->kfifo.in) - READ_ONCE(handle->kfifo.out);
        unsigned int unused = *handle->kfifo.mask + 1 - len;
        if (unused > 0)
            should_arm = 1;
    }

    if (should_arm) {
        int sfd = __ufifo_get_sender_fd();
        if (sfd >= 0) {
            sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, addr_len);
            /* Pre-arm also sets pending since we just sent a notification */
            smp_store_release(efd_flags, UFIFO_EFD_PENDING);
        }
    }

    ret_fd = *efd;

end:
    __ufifo_ctrl_unlock(handle);
    return ret_fd;
}

int ufifo_get_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get_efd(handle, 1);
}

int ufifo_get_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get_efd(handle, 0);
}

static int __ufifo_drain_efd(int fd, int *efd_flags)
{
    if (fd < 0)
        return -EINVAL;

    char buf[128];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
    }

    /* Transition: PENDING → REGISTERED (re-arm for next notification) */
    smp_store_release(efd_flags, UFIFO_EFD_REGISTERED);
    return 0;
}

int ufifo_drain_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_drain_efd(handle->rx_efd, &handle->ctrl->users[handle->user_id].efd_rx_flag);
}

int ufifo_drain_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_drain_efd(handle->tx_efd, &handle->ctrl->efd_tx_flag);
}

void ufifo_dump(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    __ufifo_ctrl_lock(handle);

    unsigned int mask = *handle->kfifo.mask;
    unsigned int size = mask + 1;
    unsigned int in = READ_ONCE(handle->kfifo.in);
    unsigned int out = READ_ONCE(handle->kfifo.out);

    printf("=== ufifo_dump: %s ===\n", handle->name);
    printf("Shm fd: %d, Size: %u (Mask: 0x%x)\n", handle->shm_fd, size, mask);
    printf("Ctrl fd: %d, Max Users: %u, Num Users: %u\n",
           handle->ctrl_fd,
           handle->ctrl->max_users,
           handle->ctrl->num_users);

    printf("Data Mode: %s\n", __ufifo_is_shared(handle) ? "SHARED" : "SOLE");

    ufifo_version_t lib_ver = { 0 };
    ufifo_get_version_info(NULL, &lib_ver);
    printf("Lib Version: %u.%u.%u (%s)\n", lib_ver.major, lib_ver.minor, lib_ver.patch, lib_ver.version);

    ufifo_version_t shm_ver = { 0 };
    ufifo_get_version_info(handle, &shm_ver);
    printf("Shm Version: %u.%u.%u (%s)\n", shm_ver.major, shm_ver.minor, shm_ver.patch, shm_ver.version);

    const char *lock_modes[] = { "NONE", "THREAD", "PROCESS" };
    const char *lock_str = (handle->ctrl->lock < UFIFO_LOCK_MAX) ? lock_modes[handle->ctrl->lock] : "UNKNOWN";
    printf("Lock Mode: %s\n", lock_str);

    printf("Pointers: in = %u (offset: %u), out = %u (offset: %u)\n", in, in & mask, out, out & mask);

    // fd epoll info
    printf("Rx Efd: %d, Tx Efd: %d\n", handle->rx_efd, handle->tx_efd);

    unsigned int i;
    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (READ_ONCE(&handle->ctrl->users[i].active)) {
            unsigned int u_out = READ_ONCE(&handle->ctrl->users[i].out);
            printf("  User[%u]: pid = %d, out = %u (offset: %u)\n", i, handle->ctrl->users[i].pid, u_out, u_out & mask);
        }
    }
    printf("=========================\n");

    __ufifo_ctrl_unlock(handle);
}

const char *ufifo_get_version(void)
{
#ifndef UFIFO_VERSION
#define UFIFO_VERSION "unknown"
#endif
    return UFIFO_VERSION;
}

int ufifo_get_version_info(ufifo_t *handle, ufifo_version_t *ver)
{
#ifndef UFIFO_VERSION_MAJOR
#define UFIFO_VERSION_MAJOR 0
#endif
#ifndef UFIFO_VERSION_MINOR
#define UFIFO_VERSION_MINOR 0
#endif
#ifndef UFIFO_VERSION_PATCH
#define UFIFO_VERSION_PATCH 0
#endif
    if (ver == NULL) {
        return -EINVAL;
    }

    if (handle == NULL) {
        ver->major = UFIFO_VERSION_MAJOR;
        ver->minor = UFIFO_VERSION_MINOR;
        ver->patch = UFIFO_VERSION_PATCH;
        snprintf(ver->version, sizeof(ver->version), "%s", ufifo_get_version());
        return 0;
    }

    UFIFO_CHECK_HANDLE_FUNC(handle);
    memcpy(ver, &handle->ctrl->ver, sizeof(*ver));
    return 0;
}
