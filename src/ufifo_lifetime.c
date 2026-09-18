#include "ufifo_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define UFIFO_INIT_RETRY_LIMIT 100U
#define UFIFO_INIT_RETRY_DELAY_US 1000U

static int __ufifo_lock_result(int ret)
{
    return (ret == -EACCES || ret == -EAGAIN) ? -EBUSY : ret;
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
    unsigned int incomplete_retries = 0;
    unsigned int missing_retries = 0;

    for (;;) {
        struct stat stat_buffer;
        int fd = shm_open(name, O_RDWR, 0);
        if (fd < 0 && errno == ENOENT && ++missing_retries < UFIFO_INIT_RETRY_LIMIT) {
            usleep(UFIFO_INIT_RETRY_DELAY_US);
            continue;
        }
        if (fd < 0)
            return -errno;
        missing_retries = 0;

        int ret = __ufifo_lifetime_lock_shared(fd, true);
        if (ret < 0) {
            close(fd);
            return ret;
        }

        ret = __ufifo_name_matches_fd(name, fd);
        if (ret == 1) {
            if (fstat(fd, &stat_buffer) < 0) {
                ret = -errno;
                close(fd);
                return ret;
            }
            if (stat_buffer.st_size >= (off_t)sizeof(ufifo_ctrl_t))
                return fd;
            close(fd);
            if (++incomplete_retries >= UFIFO_INIT_RETRY_LIMIT)
                return -EPROTO;
            usleep(UFIFO_INIT_RETRY_DELAY_US);
            continue;
        }
        close(fd);
        if (ret < 0 && ret != -ENOENT)
            return ret;
    }
}

int __ufifo_force_unlink(const char *name)
{
    uint32_t layout_abi = 0;
    int fd = shm_open(name, O_RDWR, 0);
    int ret;

    if (fd < 0)
        return errno == ENOENT ? 0 : -errno;
    ret = __ufifo_lock_result(__ufifo_lifetime_lock_exclusive(fd, false));
    if (ret < 0)
        goto out;
    ssize_t size = pread(fd, &layout_abi, sizeof(layout_abi), offsetof(ufifo_ctrl_t, layout_abi));
    if (size != (ssize_t)sizeof(layout_abi) || layout_abi != UFIFO_LAYOUT_ABI) {
        ret = -EPROTO;
        goto out;
    }
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
