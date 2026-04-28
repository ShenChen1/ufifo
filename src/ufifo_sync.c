#include "ufifo_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/eventfd.h>

#include <unistd.h>

int __ufifo_ctrl_lock(ufifo_t *handle)
{
    int ret = pthread_mutex_lock(&handle->ctrl->ctrl_mutex);
    if (ret == EOWNERDEAD) {
        pthread_mutex_consistent(&handle->ctrl->ctrl_mutex);
        ret = 0;
    }
    return ret;
}

int __ufifo_ctrl_unlock(ufifo_t *handle)
{
    return pthread_mutex_unlock(&handle->ctrl->ctrl_mutex);
}

int __ufifo_data_lock(ufifo_t *handle)
{
    if (handle->ctrl->lock == UFIFO_LOCK_NONE)
        return 0;

    int ret = pthread_mutex_lock(&handle->ctrl->data_mutex);
    if (ret == EOWNERDEAD) {
        pthread_mutex_consistent(&handle->ctrl->data_mutex);
        ret = 0;
    }
    return ret;
}

int __ufifo_data_unlock(ufifo_t *handle)
{
    if (handle->ctrl->lock == UFIFO_LOCK_NONE)
        return 0;

    return pthread_mutex_unlock(&handle->ctrl->data_mutex);
}

int __ufifo_ofd_lock(int fd, unsigned int user_id)
{
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

int __ufifo_ofd_unlock(int fd, unsigned int user_id)
{
    struct flock fl = { .l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = user_id, .l_len = 1 };
    return fcntl(fd, F_OFD_SETLK, &fl);
}

int __ufifo_is_user_dead(int fd, unsigned int user_id)
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

    if (handle->ctrl->lock != UFIFO_LOCK_NONE) {
        ret |= pthread_mutex_destroy(&handle->ctrl->data_mutex);
    }

    return ret;
}

int __ufifo_efd_create(void)
{
    return eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC);
}

int __ufifo_efd_wait(int efd, ufifo_t *handle)
{
    uint64_t val;
    int ret;

    __ufifo_data_unlock(handle);

    /* Block until eventfd becomes readable */
    struct pollfd pfd = { .fd = efd, .events = POLLIN };
    ret = poll(&pfd, 1, -1); /* infinite wait */
    if (ret > 0) {
        if (read(efd, &val, sizeof(val)) < 0)
            ret = -errno;
        else
            ret = 0;
    } else {
        ret = -errno;
    }

    __ufifo_data_lock(handle);
    return ret;
}

int __ufifo_efd_timedwait(int efd, ufifo_t *handle, long millisec)
{
    uint64_t val;
    int ret;

    __ufifo_data_unlock(handle);

    struct pollfd pfd = { .fd = efd, .events = POLLIN };
    ret = poll(&pfd, 1, (int)millisec);
    if (ret > 0) {
        if (read(efd, &val, sizeof(val)) < 0)
            ret = -errno;
        else
            ret = 0;
    } else if (ret == 0) {
        ret = ETIMEDOUT;
    } else {
        ret = -errno;
    }

    __ufifo_data_lock(handle);
    return ret;
}

int __ufifo_efd_post(int efd)
{
    uint64_t val = 1;
    int ret = write(efd, &val, sizeof(val));
    return ret < 0 ? -errno : 0;
}

int __ufifo_efd_drain(int efd)
{
    uint64_t val;
    while (read(efd, &val, sizeof(val)) > 0) {
    }
    return 0;
}
