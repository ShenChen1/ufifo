#include "ufifo_internal.h"

int __ufifo_ctrl_lock(ufifo_t *ufifo)
{
    int ret = pthread_mutex_lock(&ufifo->ctrl->ctrl_mutex);
    if (ret == EOWNERDEAD) {
        pthread_mutex_consistent(&ufifo->ctrl->ctrl_mutex);
        ret = 0;
    }
    return ret;
}

int __ufifo_ctrl_unlock(ufifo_t *ufifo)
{
    return pthread_mutex_unlock(&ufifo->ctrl->ctrl_mutex);
}

int __ufifo_data_lock(ufifo_t *ufifo)
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

int __ufifo_data_unlock(ufifo_t *ufifo)
{
    if (ufifo->ctrl->lock == UFIFO_LOCK_NONE)
        return 0;

    return pthread_mutex_unlock(&ufifo->ctrl->data_mutex);
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

int __ufifo_lock_init(ufifo_t *ufifo, ufifo_lock_e type)
{
    pthread_mutexattr_t attr;
    int ret = 0;

    ufifo->ctrl->lock = type;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
    if (type == UFIFO_LOCK_PROCESS) {
        pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    }

    /* ctrl_mutex: always initialized */
    ret = pthread_mutex_init(&ufifo->ctrl->ctrl_mutex, &attr);

    /* data_mutex: only when locking is requested */
    if (ret == 0 && type != UFIFO_LOCK_NONE) {
        ret = pthread_mutex_init(&ufifo->ctrl->data_mutex, &attr);
    }

    pthread_mutexattr_destroy(&attr);
    return ret;
}

int __ufifo_lock_deinit(ufifo_t *ufifo)
{
    int ret = pthread_mutex_destroy(&ufifo->ctrl->ctrl_mutex);

    if (ufifo->ctrl->lock != UFIFO_LOCK_NONE) {
        ret |= pthread_mutex_destroy(&ufifo->ctrl->data_mutex);
    }

    return ret;
}

int __ufifo_bsem_init(sem_t *bsem, unsigned int value)
{
    return sem_init(bsem, 1, value);
}

int __ufifo_bsem_deinit(sem_t *bsem)
{
    return sem_destroy(bsem);
}

int __ufifo_bsem_wait(sem_t *bsem, ufifo_t *ufifo)
{
    int ret;

    __ufifo_data_unlock(ufifo);
    ret = sem_wait(bsem);
    __ufifo_data_lock(ufifo);

    return ret;
}

int __ufifo_bsem_timedwait(sem_t *bsem, ufifo_t *ufifo, long millisec)
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

int __ufifo_bsem_post(sem_t *bsem)
{
    sem_trywait(bsem);
    return sem_post(bsem);
}
