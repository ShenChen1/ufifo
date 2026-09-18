#include "ufifo_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
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
