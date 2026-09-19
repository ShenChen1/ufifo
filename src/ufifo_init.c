#include "ufifo_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log2.h"
#include "utils.h"

#define UFIFO_DATA_ALIGNMENT 64U

bool __ufifo_reap_dead_user(ufifo_t *handle, size_t user_id)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;

    if (!READ_ONCE(&ctrl->users[user_id].active) || !__ufifo_is_user_dead(handle->shm_fd, user_id))
        return false;
    smp_store_release(&ctrl->users[user_id].active, false);
    ctrl->num_users--;
    return true;
}

static int __ufifo_register_slot(ufifo_t *handle, size_t user_id, pid_t pid)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;
    int ret = __ufifo_ofd_lock(handle->shm_fd, user_id);

    if (ret < 0)
        return ret;
    if (ctrl->data_mode == UFIFO_DATA_SHARED)
        WRITE_ONCE(&ctrl->users[user_id].out, READ_ONCE(&ctrl->in));
    ctrl->users[user_id].pid = pid;
    smp_store_release(&ctrl->users[user_id].active, true);
    ctrl->num_users++;
    return 0;
}

static int __ufifo_register(ufifo_t *handle, size_t *user_id)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;
    pid_t pid = getpid();

    for (size_t i = 0; i < ctrl->max_users; i++) {
        if (!READ_ONCE(&ctrl->users[i].active)) {
            int ret = __ufifo_register_slot(handle, i, pid);
            if (ret == 0)
                *user_id = i;
            return ret;
        }
    }

    for (size_t i = 0; i < ctrl->max_users; i++) {
        if (!__ufifo_reap_dead_user(handle, i))
            continue;
        int ret = __ufifo_register_slot(handle, i, pid);
        if (ret == 0)
            *user_id = i;
        return ret;
    }
    return -ENOSPC;
}

static void __ufifo_unregister(ufifo_t *handle)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;

    if (!handle->registered)
        return;
    if (handle->user_id >= ctrl->max_users || !READ_ONCE(&ctrl->users[handle->user_id].active)) {
        handle->registered = false;
        return;
    }
    smp_store_release(&ctrl->users[handle->user_id].active, false);
    __ufifo_ofd_unlock(handle->shm_fd, handle->user_id);
    ctrl->num_users--;
    handle->registered = false;
    __ufifo_update_cached_min_out(handle);
    __ufifo_notify_writers(handle);
}

static void __ufifo_hook_init(ufifo_t *handle, const ufifo_hook_t *hook)
{
    handle->hook = *hook;
}

static int __ufifo_compatibility_check(const ufifo_ctrl_t *ctrl)
{
    ufifo_version_t ver = {};
    ufifo_get_version_info(NULL, &ver);

    if (ctrl->layout_abi != UFIFO_LAYOUT_ABI) {
        __ufifo_log("ufifo: shared layout mismatch (shm=%u, lib=%u)\n", ctrl->layout_abi, UFIFO_LAYOUT_ABI);
        return -EPROTO;
    }
    if (ctrl->ver.major != ver.major) {
        __ufifo_log("ufifo: version mismatch (shm=%u.%u.%u, lib=%u.%u.%u)\n",
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

static int __ufifo_checked_add(size_t left, size_t right, size_t *result)
{
    if (left > SIZE_MAX - right)
        return -EOVERFLOW;
    *result = left + right;
    return 0;
}

static int __ufifo_checked_mul(size_t left, size_t right, size_t *result)
{
    if (left != 0 && right > SIZE_MAX / left)
        return -EOVERFLOW;
    *result = left * right;
    return 0;
}

static int __ufifo_align_up(size_t value, size_t alignment, size_t *result)
{
    size_t remainder = value % alignment;
    return remainder == 0 ? (*result = value, 0) : __ufifo_checked_add(value, alignment - remainder, result);
}

static bool __ufifo_fits_off_t(size_t value)
{
    off_t converted = (off_t)value;
    return converted >= 0 && (uintmax_t)converted == (uintmax_t)value;
}

static int
__ufifo_calculate_layout(const ufifo_alloc_t *alloc, size_t *data_offset, size_t *data_size, size_t *mapping_size)
{
    size_t users_size;
    size_t control_size;
    if (alloc->max_users == SIZE_MAX)
        return -EOVERFLOW;
    size_t slot_count = alloc->max_users + 1;
    int ret = __ufifo_checked_mul(slot_count, sizeof(ufifo_sub_ctrl_t), &users_size);

    if (ret < 0)
        return ret;
    ret = __ufifo_checked_add(sizeof(ufifo_ctrl_t), users_size, &control_size);
    if (ret < 0)
        return ret;
    ret = __ufifo_align_up(control_size, UFIFO_DATA_ALIGNMENT, data_offset);
    if (ret < 0)
        return ret;
    *data_size = roundup_pow_of_two(alloc->size);
    if (*data_size == 0)
        return -EOVERFLOW;
    if (*data_size < 2)
        *data_size = 2;
    if (*data_size > SSIZE_MAX)
        return -EOVERFLOW;
    return __ufifo_checked_add(*data_offset, *data_size, mapping_size);
}

static int __ufifo_expected_data_offset(size_t max_users, size_t *data_offset)
{
    size_t users_size;
    size_t control_size;
    if (max_users == SIZE_MAX)
        return -EOVERFLOW;
    int ret = __ufifo_checked_mul(max_users + 1, sizeof(ufifo_sub_ctrl_t), &users_size);

    if (ret < 0)
        return ret;
    ret = __ufifo_checked_add(sizeof(ufifo_ctrl_t), users_size, &control_size);
    return ret < 0 ? ret : __ufifo_align_up(control_size, UFIFO_DATA_ALIGNMENT, data_offset);
}

static int __ufifo_validate_layout(ufifo_t *handle, size_t file_size)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;
    size_t expected_offset;
    size_t expected_mapping;
    int ret = __ufifo_compatibility_check(ctrl);

    if (ret < 0)
        return ret;
    if (ctrl->max_users < 1 || ctrl->lock >= UFIFO_LOCK_MAX || ctrl->data_mode >= UFIFO_DATA_MAX)
        return -EPROTO;
    ret = __ufifo_expected_data_offset(ctrl->max_users, &expected_offset);
    if (ret < 0 || ctrl->data_offset != expected_offset)
        return -EPROTO;
    if (ctrl->data_size < 2 || ctrl->data_size > SSIZE_MAX
        || (ctrl->data_size & (ctrl->data_size - 1)) != 0)
        return -EPROTO;
    ret = __ufifo_checked_add(ctrl->data_offset, ctrl->data_size, &expected_mapping);
    if (ret < 0 || ctrl->mapping_size != expected_mapping || ctrl->mapping_size != file_size)
        return -EPROTO;
    if (ctrl->mask != ctrl->data_size - 1)
        return -EPROTO;
    return 0;
}

static int __ufifo_configure_data(ufifo_t *handle, bool initialize)
{
    handle->is_shared = handle->ctrl->data_mode == UFIFO_DATA_SHARED;
    handle->lock_type = handle->ctrl->lock;
    handle->kfifo.in = &handle->ctrl->in;
    handle->kfifo.out = &__ufifo_rx_ctrl(handle)->out;
    if (initialize)
        return kfifo_init(&handle->kfifo, handle->shm_size);
    handle->kfifo.mask = handle->ctrl->mask;
    return 0;
}

static int __ufifo_register_handle(ufifo_t *handle, bool initialize)
{
    size_t user_id;
    int ret;

    ret = __ufifo_ctrl_lock(handle);
    if (ret < 0)
        return ret;
    ret = __ufifo_register(handle, &user_id);
    int unlock_ret = __ufifo_ctrl_unlock(handle);
    if (ret < 0)
        return ret;
    if (unlock_ret < 0)
        return unlock_ret;
    handle->user_id = user_id;
    handle->registered = true;
    ret = __ufifo_configure_data(handle, initialize);
    if (ret < 0) {
        if (__ufifo_ctrl_lock(handle) == 0) {
            __ufifo_unregister(handle);
            __ufifo_ctrl_unlock(handle);
        }
        return ret;
    }
    if (__ufifo_is_shared(handle)) {
        __ufifo_update_cached_min_out(handle);
        __ufifo_notify_writers(handle);
    }
    return 0;
}

static void __ufifo_unmap(ufifo_t *handle)
{
    if (handle->ctrl != NULL) {
        munmap(handle->ctrl, handle->mapping_size);
        handle->ctrl = NULL;
        handle->shm_mem = NULL;
    }
}

static int __ufifo_init_from_shm(ufifo_t *handle)
{
    struct stat stat_buffer;
    void *mapping;
    int ret;

    if (fstat(handle->shm_fd, &stat_buffer) < 0)
        return -errno;
    if (stat_buffer.st_size < (off_t)sizeof(ufifo_ctrl_t) || (uintmax_t)stat_buffer.st_size > SIZE_MAX)
        return -EPROTO;
    handle->mapping_size = (size_t)stat_buffer.st_size;
    mapping = mmap(NULL, handle->mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, handle->shm_fd, 0);
    if (mapping == MAP_FAILED)
        return -errno;
    handle->ctrl = mapping;
    ret = __ufifo_validate_layout(handle, handle->mapping_size);
    if (ret < 0)
        goto error;

    handle->shm_size = handle->ctrl->data_size;
    handle->shm_mem = (char *)mapping + handle->ctrl->data_offset;
    ret = __ufifo_register_handle(handle, false);
    if (ret < 0)
        goto error;
    return 0;

error:
    __ufifo_unmap(handle);
    return ret;
}

static int __ufifo_init_from_user(ufifo_t *handle, const ufifo_alloc_t *alloc)
{
    size_t data_offset;
    if (alloc->max_users == SIZE_MAX)
        return -EOVERFLOW;
    size_t slot_count = alloc->max_users + 1;
    int ret = __ufifo_calculate_layout(alloc, &data_offset, &handle->shm_size, &handle->mapping_size);

    if (ret < 0)
        return ret;
    if (!__ufifo_fits_off_t(handle->mapping_size))
        return -EOVERFLOW;
    if (ftruncate(handle->shm_fd, handle->mapping_size) < 0)
        return -errno;
    handle->ctrl = mmap(NULL, handle->mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, handle->shm_fd, 0);
    if (handle->ctrl == MAP_FAILED) {
        handle->ctrl = NULL;
        return -errno;
    }
    handle->shm_mem = (char *)handle->ctrl + data_offset;
    ret = __ufifo_lock_init(handle, alloc->lock);
    if (ret < 0)
        goto error_mapping;

    handle->ctrl->layout_abi = UFIFO_LAYOUT_ABI;
    handle->ctrl->mapping_size = handle->mapping_size;
    handle->ctrl->data_offset = data_offset;
    handle->ctrl->data_size = handle->shm_size;
    handle->ctrl->data_mode = alloc->data_mode;
    handle->ctrl->max_users = alloc->max_users;
    handle->ctrl->num_users = 0;
    memset(handle->ctrl->users, 0, slot_count * sizeof(ufifo_sub_ctrl_t));

    ret = __ufifo_register_handle(handle, true);
    if (ret < 0)
        goto error_lock;
    handle->ctrl->mask = handle->kfifo.mask;
    ufifo_get_version_info(NULL, &handle->ctrl->ver);
    ret = __ufifo_lifetime_lock_shared(handle->shm_fd, false);
    if (ret == 0)
        return 0;

    if (__ufifo_ctrl_lock(handle) == 0) {
        __ufifo_unregister(handle);
        __ufifo_ctrl_unlock(handle);
    }
error_lock:
    __ufifo_lock_deinit(handle);
error_mapping:
    __ufifo_unmap(handle);
    return ret;
}

static int __ufifo_init_validate(const ufifo_init_t *init)
{
    if (init->opt >= UFIFO_OPT_MAX)
        return -EINVAL;
    if (init->opt != UFIFO_OPT_ALLOC)
        return 0;
    if (init->alloc.size == 0 || init->alloc.max_users < 1 || init->alloc.max_users == SIZE_MAX)
        return -EINVAL;
    if (init->alloc.lock >= UFIFO_LOCK_MAX || init->alloc.data_mode >= UFIFO_DATA_MAX)
        return -EINVAL;
    return 0;
}

int ufifo_open(const char *name, const ufifo_init_t *init, ufifo_t **handle)
{
    ufifo_init_t fifo_init;
    ufifo_t *fifo;
    bool is_alloc = false;
    int ret;

    if (name == NULL || init == NULL || handle == NULL)
        return -EINVAL;
    *handle = NULL;
    if (name[0] == '\0')
        return -EINVAL;
    if (strlen(name) > UFIFO_NAME_MAX)
        return -ENAMETOOLONG;
    ret = __ufifo_init_validate(init);
    if (ret < 0)
        return ret;

    fifo_init = *init;
    fifo = calloc(1, sizeof(*fifo));
    if (fifo == NULL)
        return -ENOMEM;
    strncpy(fifo->name, name, sizeof(fifo->name) - 1);
    fifo->owner_pid = getpid();
    __ufifo_hook_init(fifo, &fifo_init.hook);
    ret = __ufifo_open_fd(name, &fifo_init, &is_alloc);
    if (ret < 0)
        goto error_handle;
    fifo->shm_fd = ret;

    if (is_alloc)
        ret = __ufifo_init_from_user(fifo, &fifo_init.alloc);
    else
        ret = __ufifo_init_from_shm(fifo);
    if (ret < 0)
        goto error_fd;

    fifo->magic = UFIFO_MAGIC;
    *handle = fifo;
    return 0;

error_fd:
    close(fifo->shm_fd);
    if (is_alloc)
        shm_unlink(fifo->name);
error_handle:
    free(fifo);
    return ret;
}

static void __ufifo_release_handle(ufifo_t *handle)
{
    __ufifo_unmap(handle);
    close(handle->shm_fd);
    handle->magic = 0;
    free(handle);
}

static int __ufifo_close(ufifo_t *handle, bool destroy)
{
    int ret;

    if (destroy) {
        ret = __ufifo_lifetime_lock_exclusive(handle->shm_fd, false);
        if (ret == -EACCES || ret == -EAGAIN)
            return -EBUSY;
        if (ret < 0)
            return ret;
        ret = __ufifo_name_matches_fd(handle->name, handle->shm_fd);
        if (ret == 0 || (ret < 0 && ret != -ENOENT)) {
            __ufifo_lifetime_lock_shared(handle->shm_fd, false);
            return ret == 0 ? -ESTALE : ret;
        }
        if (ret == 1 && shm_unlink(handle->name) < 0 && errno != ENOENT) {
            ret = -errno;
            __ufifo_lifetime_lock_shared(handle->shm_fd, false);
            return ret;
        }
    }

    ret = __ufifo_ctrl_lock(handle);
    if (ret < 0) {
        if (destroy)
            __ufifo_lifetime_lock_shared(handle->shm_fd, false);
        return ret;
    }
    __ufifo_unregister(handle);
    ret = __ufifo_ctrl_unlock(handle);
    if (ret < 0) {
        if (destroy)
            __ufifo_lifetime_lock_shared(handle->shm_fd, false);
        return ret;
    }
    if (destroy)
        __ufifo_lock_deinit(handle);
    __ufifo_release_handle(handle);
    return 0;
}

int ufifo_close(ufifo_t *handle)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret == 0)
        ret = __ufifo_close(handle, false);
    if (ret < 0)
        errno = -ret;
    return ret;
}

int ufifo_destroy(ufifo_t *handle)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret == 0)
        ret = __ufifo_close(handle, true);
    if (ret < 0)
        errno = -ret;
    return ret;
}
