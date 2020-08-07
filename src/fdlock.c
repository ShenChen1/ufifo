#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "fdlock.h"

struct fdlock {
    int fd;
    char *path;
};

static bool check_fd_inode_same_as_path(int fd, const char *path, bool result_for_errors)
{
    struct stat st_fd;
    struct stat st_path;
    if (fstat(fd, &st_fd) == -1 || stat(path, &st_path) == -1) {
        return result_for_errors;
    }

    return st_fd.st_dev == st_path.st_dev && st_fd.st_ino == st_path.st_ino;
}

int fdlock_acquire(const char *lock_path, fdlock_t **out_lock_handle)
{
    char *dup_lock_path = strdup(lock_path);
    fdlock_t *lock_handle = malloc(sizeof(fdlock_t));
    if (dup_lock_path == NULL || lock_handle == NULL) {
        free(dup_lock_path);
        free(lock_handle);
        return -ENOMEM;
    }

    int lock_fd = -1;
    do {
        if (lock_fd >= 0) {
            close(lock_fd);
        }

        lock_fd = open(lock_path, O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
        if (lock_fd < 0) {
            break;
        }

        int flock_status;
        do {
            flock_status = flock(lock_fd, LOCK_EX);
        } while (flock_status == -1 && errno == EINTR);

        if (flock_status == -1) {
            close(lock_fd);
            break;
        }
    } while (!check_fd_inode_same_as_path(lock_fd, lock_path, false));

    int ret;
    if (lock_fd >= 0) {
        lock_handle->fd = lock_fd;
        lock_handle->path = dup_lock_path;
        *out_lock_handle = lock_handle;
        ret = 0;
    } else {
        free(dup_lock_path);
        free(lock_handle);
        ret = -EPERM;
    }

    return ret;
}

int fdlock_release(fdlock_t **lock_handle_ptr)
{
    fdlock_t *lock_handle = *lock_handle_ptr;

    unlink(lock_handle->path);
    flock(lock_handle->fd, LOCK_UN);
    close(lock_handle->fd);

    free(lock_handle->path);
    free(lock_handle);

    *lock_handle_ptr = NULL;

    return 0;
}