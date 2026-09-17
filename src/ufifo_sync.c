#include "ufifo_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "utils.h"

void __ufifo_recover_state(ufifo_t *handle)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;
    size_t count = 0;
    size_t i;

    for (i = 0; i < ctrl->max_users; i++) {
        if (smp_load_acquire(&ctrl->users[i].active)) {
            if (__ufifo_is_user_dead(handle->ctrl_fd, i)) {
                smp_store_release(&ctrl->users[i].active, false);
            } else {
                count++;
            }
        }
    }

    ctrl->num_users = count;

    if (__ufifo_is_shared(handle)) {
        __ufifo_update_cached_min_out(handle);
    }
}

int __ufifo_ctrl_lock(ufifo_t *handle)
{
    int ret = pthread_mutex_lock(&handle->ctrl->ctrl_mutex);
    if (ret == EOWNERDEAD) {
        __ufifo_log("WARN: ctrl_mutex owner died, recovering state\n");
        __ufifo_recover_state(handle);
        pthread_mutex_consistent(&handle->ctrl->ctrl_mutex);
        ret = 0;
    } else if (ret != 0) {
        __ufifo_log("FATAL: ufifo ctrl_mutex lock failed (err=%d)\n", ret);
        abort();
    }
    return ret;
}

int __ufifo_ctrl_unlock(ufifo_t *handle)
{
    return pthread_mutex_unlock(&handle->ctrl->ctrl_mutex);
}

int __ufifo_data_lock(ufifo_t *handle)
{
    if (handle->lock_type == UFIFO_LOCK_NONE)
        return 0;

    int ret = pthread_mutex_lock(&handle->ctrl->data_mutex);
    if (ret == EOWNERDEAD) {
        pthread_mutex_consistent(&handle->ctrl->data_mutex);
        ret = 0;
    } else if (ret != 0) {
        __ufifo_log("FATAL: ufifo data_mutex lock failed (err=%d)\n", ret);
        abort();
    }
    return ret;
}

int __ufifo_data_unlock(ufifo_t *handle)
{
    if (handle->lock_type == UFIFO_LOCK_NONE)
        return 0;

    return pthread_mutex_unlock(&handle->ctrl->data_mutex);
}

int __ufifo_ofd_lock(int fd, size_t user_id)
{
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

int __ufifo_ofd_unlock(int fd, size_t user_id)
{
    struct flock fl = { .l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

int __ufifo_is_user_dead(int fd, size_t user_id)
{
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    if (fcntl(fd, F_OFD_GETLK, &fl) < 0)
        return 0;                /* cannot query, be conservative */
    return fl.l_type == F_UNLCK; /* unlocked = holder is dead */
}

int __ufifo_init_lock(int fd)
{
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

int __ufifo_init_wait(int fd)
{
    struct flock fl = { .l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLKW, &fl);
}

int __ufifo_init_unlock(int fd)
{
    struct flock fl = { .l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

int __ufifo_lock_init(ufifo_t *handle, ufifo_lock_e type)
{
    pthread_mutexattr_t attr;
    int ret = 0;

    handle->ctrl->lock = type;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if (type == UFIFO_LOCK_PROCESS) {
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    }

    /* ctrl_mutex: always initialized */
    ret = pthread_mutex_init(&handle->ctrl->ctrl_mutex, &attr);

    /* data_mutex: only when locking is requested */
    if (ret == 0 && type != UFIFO_LOCK_NONE) {
        ret = pthread_mutex_init(&handle->ctrl->data_mutex, &attr);
    }

    pthread_mutexattr_destroy(&attr);
    return ret;
}

int __ufifo_lock_deinit(ufifo_t *handle)
{
    int ret = pthread_mutex_destroy(&handle->ctrl->ctrl_mutex);

    if (handle->lock_type != UFIFO_LOCK_NONE) {
        ret |= pthread_mutex_destroy(&handle->ctrl->data_mutex);
    }

    return ret;
}

/* ------------------------------------------------------------------ */
/*  Futex-based wait/notify                                            */
/* ------------------------------------------------------------------ */

/*
 * Block until the futex variable changes from its current value.
 * Releases data_mutex before sleeping and re-acquires it after waking.
 * Returns 0 on success (woken or spurious), never propagates EAGAIN/EINTR.
 */
int __ufifo_futex_wait(uint32_t *futex, ufifo_t *handle)
{
    uint32_t snapshot = smp_load_acquire(futex);

    __ufifo_data_unlock(handle);
    /* EAGAIN (value changed) and EINTR are both benign — just retry */
    syscall(SYS_futex, futex, FUTEX_WAIT, snapshot, NULL, NULL, 0);
    __ufifo_data_lock(handle);

    return 0;
}

/*
 * Block until the futex variable changes, with a timeout in milliseconds.
 * Returns 0 on success/spurious wake, ETIMEDOUT on expiry.
 */
int __ufifo_futex_timedwait(uint32_t *futex, ufifo_t *handle, long millisec)
{
    uint32_t snapshot = smp_load_acquire(futex);
    struct timespec ts = { .tv_sec = millisec / 1000, .tv_nsec = (millisec % 1000) * 1000000L };

    __ufifo_data_unlock(handle);
    int ret = syscall(SYS_futex, futex, FUTEX_WAIT, snapshot, &ts, NULL, 0);
    __ufifo_data_lock(handle);

    if (ret < 0 && errno == ETIMEDOUT)
        return ETIMEDOUT;
    return 0;
}

/*
 * Wake all threads waiting on this futex variable.
 * Increments the futex counter to invalidate any pending FUTEX_WAIT snapshots.
 * No-op when no waiters are registered and epoll is not armed.
 */
void __ufifo_futex_notify(uint32_t *futex, int32_t *waiters, int32_t *armed)
{
    bool need_wake = false;
    if (smp_load_acquire(waiters) > 0) {
        need_wake = true;
    }
    if (armed && atomic_xchg(armed, 0) == 1) {
        need_wake = true;
    }
    if (need_wake) {
        __atomic_fetch_add(futex, 1, __ATOMIC_RELEASE);
        syscall(SYS_futex, futex, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    }
}
