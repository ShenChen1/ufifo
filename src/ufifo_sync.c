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
        if (handle->registered && i == handle->user_id) {
            if (smp_load_acquire(&ctrl->users[i].active))
                count++;
            continue;
        }
        if (smp_load_acquire(&ctrl->users[i].active)) {
            if (__ufifo_is_user_dead(handle->shm_fd, i)) {
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
        ret = pthread_mutex_consistent(&handle->ctrl->ctrl_mutex);
    }
    return ret == 0 ? 0 : -ret;
}

int __ufifo_ctrl_unlock(ufifo_t *handle)
{
    int ret = pthread_mutex_unlock(&handle->ctrl->ctrl_mutex);
    return ret == 0 ? 0 : -ret;
}

int __ufifo_data_lock(ufifo_t *handle)
{
    if (handle->lock_type == UFIFO_LOCK_NONE)
        return 0;

    int ret = pthread_mutex_lock(&handle->ctrl->data_mutex);
    if (ret == EOWNERDEAD) {
        __ufifo_reset_data_locked(handle);
        int consistent_ret = pthread_mutex_consistent(&handle->ctrl->data_mutex);
        if (consistent_ret == 0) {
            __ufifo_notify_readers(handle);
            __ufifo_notify_writers(handle);
        }
        int unlock_ret = pthread_mutex_unlock(&handle->ctrl->data_mutex);
        if (consistent_ret != 0)
            return -consistent_ret;
        if (unlock_ret != 0)
            return -unlock_ret;
        return -EOWNERDEAD;
    }
    return ret == 0 ? 0 : -ret;
}

int __ufifo_data_unlock(ufifo_t *handle)
{
    if (handle->lock_type == UFIFO_LOCK_NONE)
        return 0;

    int ret = pthread_mutex_unlock(&handle->ctrl->data_mutex);
    return ret == 0 ? 0 : -ret;
}

static int __ufifo_set_ofd_lock(int fd, short type, off_t start, off_t len, int command)
{
    struct flock fl = { .l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len };
    return fcntl(fd, command, &fl) == 0 ? 0 : -errno;
}

int __ufifo_ofd_lock(int fd, size_t user_id)
{
    return __ufifo_set_ofd_lock(fd, F_WRLCK, UFIFO_USER_LOCK_OFFSET(user_id), 1, F_OFD_SETLK);
}

int __ufifo_ofd_unlock(int fd, size_t user_id)
{
    return __ufifo_set_ofd_lock(fd, F_UNLCK, UFIFO_USER_LOCK_OFFSET(user_id), 1, F_OFD_SETLK);
}

int __ufifo_is_user_dead(int fd, size_t user_id)
{
    struct flock fl = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = UFIFO_USER_LOCK_OFFSET(user_id),
        .l_len = 1,
    };
    if (fcntl(fd, F_OFD_GETLK, &fl) < 0)
        return 0;                /* cannot query, be conservative */
    return fl.l_type == F_UNLCK; /* unlocked = holder is dead */
}

int __ufifo_lifetime_lock_exclusive(int fd, bool wait)
{
    const int command = wait ? F_OFD_SETLKW : F_OFD_SETLK;
    return __ufifo_set_ofd_lock(fd, F_WRLCK, UFIFO_LIFETIME_LOCK_OFFSET, 1, command);
}

int __ufifo_lifetime_lock_shared(int fd, bool wait)
{
    const int command = wait ? F_OFD_SETLKW : F_OFD_SETLK;
    return __ufifo_set_ofd_lock(fd, F_RDLCK, UFIFO_LIFETIME_LOCK_OFFSET, 1, command);
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
    return ret == 0 ? 0 : -ret;
}

int __ufifo_lock_deinit(ufifo_t *handle)
{
    int ret = pthread_mutex_destroy(&handle->ctrl->ctrl_mutex);

    if (handle->lock_type != UFIFO_LOCK_NONE) {
        ret |= pthread_mutex_destroy(&handle->ctrl->data_mutex);
    }

    return ret == 0 ? 0 : -ret;
}
