#include "ufifo_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int __ufifo_lock_result(int ret)
{
    return (ret == -EACCES || ret == -EAGAIN) ? -EBUSY : ret;
}

static int __ufifo_create_fd(const char *name, bool force)
{
    for (;;) {
        if (force) {
            int ret = __ufifo_force_unlink(name);
            if (ret < 0)
                return ret;
        }
        int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            if (errno == EEXIST && force)
                continue;
            return -errno;
        }
        int ret = __ufifo_lifetime_lock_exclusive(fd, true);
        if (ret == 0)
            return fd;
        close(fd);
        shm_unlink(name);
        return ret;
    }
}

int __ufifo_open_fd(const char *name, ufifo_init_t *init, bool *is_alloc)
{
    if (init->opt == UFIFO_OPT_ATTACH)
        return __ufifo_open_attached_fd(name);
    int fd = __ufifo_create_fd(name, init->alloc.force != 0);
    if (fd >= 0) {
        *is_alloc = true;
        return fd;
    }
    if (fd != -EEXIST)
        return fd;
    init->opt = UFIFO_OPT_ATTACH;
    return __ufifo_open_attached_fd(name);
}

int __ufifo_name_matches_fd(const char *name, int fd)
{
    struct stat candidate_stat;
    struct stat current_stat;
    int current_fd = shm_open(name, O_RDWR, 0);

    if (current_fd < 0)
        return -errno;
    if (fstat(fd, &candidate_stat) < 0 || fstat(current_fd, &current_stat) < 0) {
        int ret = -errno;
        close(current_fd);
        return ret;
    }

    close(current_fd);
    return candidate_stat.st_dev == current_stat.st_dev && candidate_stat.st_ino == current_stat.st_ino;
}

int __ufifo_open_attached_fd(const char *name)
{
    struct stat stat_buffer;
    int fd = shm_open(name, O_RDWR, 0);

    if (fd < 0)
        return -errno;

    int ret = __ufifo_lifetime_lock_shared(fd, false);
    if (ret == -EACCES || ret == -EAGAIN)
        ret = -EAGAIN;
    if (ret < 0)
        goto error;
    ret = __ufifo_name_matches_fd(name, fd);
    if (ret != 1) {
        if (ret == 0 || ret == -ENOENT)
            ret = -EAGAIN;
        goto error;
    }
    if (fstat(fd, &stat_buffer) < 0) {
        ret = -errno;
        goto error;
    }
    if (stat_buffer.st_size < (off_t)sizeof(ufifo_ctrl_t)) {
        ret = -EAGAIN;
        goto error;
    }
    return fd;

error:
    close(fd);
    return ret;
}

int __ufifo_force_unlink(const char *name)
{
    int fd = shm_open(name, O_RDWR, 0);
    int ret;

    if (fd < 0)
        return errno == ENOENT ? 0 : -errno;
    ret = __ufifo_lock_result(__ufifo_lifetime_lock_exclusive(fd, false));
    if (ret < 0)
        goto out;
    ret = __ufifo_name_matches_fd(name, fd);
    if (ret != 1) {
        ret = ret < 0 ? ret : -ESTALE;
        goto out;
    }
    ret = shm_unlink(name) == 0 || errno == ENOENT ? 0 : -errno;

out:
    close(fd);
    return ret;
}
