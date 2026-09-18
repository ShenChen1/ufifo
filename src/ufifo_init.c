#include "ufifo_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log2.h"
#include "utils.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

void __ufifo_reap_dead_user(ufifo_t *handle, size_t user_id)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;

    if (READ_ONCE(&ctrl->users[user_id].active)) {
        smp_store_release(&ctrl->users[user_id].active, false);
        ctrl->num_users--;
    }
}

/* ------------------------------------------------------------------ */
/*  User registration                                                  */
/* ------------------------------------------------------------------ */

static int __ufifo_register(ufifo_t *handle)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;
    size_t i;
    pid_t mypid = getpid();

    for (i = 0; i < ctrl->max_users; i++) {
        if (!READ_ONCE(&ctrl->users[i].active)) {
            if (ctrl->data_mode == UFIFO_DATA_SHARED)
                WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(handle->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, true);
            ctrl->num_users++;
            return i;
        }
    }

    for (i = 0; i < ctrl->max_users; i++) {
        if (READ_ONCE(&ctrl->users[i].active) && __ufifo_is_user_dead(handle->ctrl_fd, i)) {
            __ufifo_reap_dead_user(handle, i);
            if (ctrl->data_mode == UFIFO_DATA_SHARED)
                WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(handle->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, true);
            ctrl->num_users++;
            return i;
        }
    }

    return -ENOSPC;
}

static void __ufifo_unregister(ufifo_t *handle)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;

    if (handle->user_id < ctrl->max_users && READ_ONCE(&ctrl->users[handle->user_id].active)) {
        smp_store_release(&ctrl->users[handle->user_id].active, false);
        __ufifo_ofd_unlock(handle->ctrl_fd, handle->user_id);
        ctrl->num_users--;
        __ufifo_update_cached_min_out(handle);
        __ufifo_notify_writers(handle);
    }
}

/* ------------------------------------------------------------------ */
/*  Hook + version                                                     */
/* ------------------------------------------------------------------ */

static int __ufifo_hook_init(ufifo_t *handle, ufifo_hook_t *hook)
{
    handle->hook.recsize = hook->recsize;
    handle->hook.rectag = hook->rectag;
    handle->hook.recput = hook->recput;
    handle->hook.recget = hook->recget;
    return 0;
}

static int __ufifo_compatibility_check(ufifo_ctrl_t *ctrl)
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

/* ------------------------------------------------------------------ */
/*  ATTACH path                                                        */
/* ------------------------------------------------------------------ */

static int __ufifo_init_from_shm(ufifo_t *handle)
{
    int ret = 0;
    struct stat st;
    char ctrl_name[UFIFO_CTRL_NAME_BUF_SIZE];

    snprintf(ctrl_name, sizeof(ctrl_name), "%s%s", handle->name, UFIFO_CTRL_NAME_SUFFIX);
    handle->ctrl_fd = shm_open(ctrl_name, O_RDWR, (S_IRUSR | S_IWUSR));
    if (handle->ctrl_fd < 0) {
        ret = -errno;
        goto end;
    }

    ret = fstat(handle->ctrl_fd, &st);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    handle->ctrl_size = st.st_size;
    handle->ctrl = mmap(NULL, handle->ctrl_size, (PROT_READ | PROT_WRITE), MAP_SHARED, handle->ctrl_fd, 0);
    if (handle->ctrl == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    ret = __ufifo_compatibility_check(handle->ctrl);
    if (ret < 0)
        goto err_ctrl_mmap;
    if (!smp_load_acquire(&handle->ctrl->init_done)) {
        ret = -EIO;
        goto err_ctrl_mmap;
    }

    ret = fstat(handle->shm_fd, &st);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    handle->shm_size = st.st_size;
    handle->shm_mem = mmap(NULL, handle->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, handle->shm_fd, 0);
    if (handle->shm_mem == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    __ufifo_ctrl_lock(handle);
    ret = __ufifo_register(handle);
    __ufifo_ctrl_unlock(handle);
    if (ret < 0)
        goto err_data_mmap;
    handle->user_id = (size_t)ret;
    handle->is_shared = (handle->ctrl->data_mode == UFIFO_DATA_SHARED);
    handle->lock_type = handle->ctrl->lock;

    handle->kfifo.in = &handle->ctrl->in;
    handle->kfifo.mask = handle->ctrl->mask;
    handle->kfifo.out = &__ufifo_rx_ctrl(handle)->out;

    if (__ufifo_is_shared(handle)) {
        __ufifo_update_cached_min_out(handle);
        __ufifo_notify_writers(handle);
    }

    return 0;

err_data_mmap:
    munmap(handle->shm_mem, handle->shm_size);
err_ctrl_mmap:
    munmap(handle->ctrl, handle->ctrl_size);
err_ctrl_fd:
    close(handle->ctrl_fd);
end:
    return ret;
}

/* ------------------------------------------------------------------ */
/*  ALLOC path                                                         */
/* ------------------------------------------------------------------ */

static int __ufifo_init_from_user(ufifo_t *handle, ufifo_alloc_t *alloc)
{
    int ret = 0;
    size_t i;
    size_t slot_count = alloc->max_users + 1;
    char ctrl_name[UFIFO_CTRL_NAME_BUF_SIZE];

    if (!alloc->size)
        return -EINVAL;

    snprintf(ctrl_name, sizeof(ctrl_name), "%s%s", handle->name, UFIFO_CTRL_NAME_SUFFIX);
    handle->ctrl_size = sizeof(ufifo_ctrl_t) + slot_count * sizeof(ufifo_sub_ctrl_t);
    handle->ctrl_fd = shm_open(ctrl_name, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR));
    if (handle->ctrl_fd < 0) {
        ret = -errno;
        goto end;
    }

    ret = ftruncate(handle->ctrl_fd, handle->ctrl_size);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    handle->ctrl = mmap(NULL, handle->ctrl_size, (PROT_READ | PROT_WRITE), MAP_SHARED, handle->ctrl_fd, 0);
    if (handle->ctrl == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    WRITE_ONCE(&handle->ctrl->init_done, false);

    ret = __ufifo_lock_init(handle, alloc->lock);
    if (ret < 0)
        goto err_ctrl_mmap;

    handle->ctrl->data_mode = alloc->data_mode;
    handle->ctrl->max_users = alloc->max_users;
    handle->ctrl->num_users = 0;
    handle->ctrl->layout_abi = UFIFO_LAYOUT_ABI;
    for (i = 0; i < slot_count; i++)
        memset(&handle->ctrl->users[i], 0, sizeof(handle->ctrl->users[i]));

    handle->shm_size = roundup_pow_of_two(alloc->size);
    ret = ftruncate(handle->shm_fd, handle->shm_size);
    if (ret < 0) {
        ret = -errno;
        goto err_lock;
    }

    handle->shm_mem = mmap(NULL, handle->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, handle->shm_fd, 0);
    if (handle->shm_mem == MAP_FAILED) {
        ret = -errno;
        goto err_lock;
    }

    __ufifo_ctrl_lock(handle);
    ret = __ufifo_register(handle);
    __ufifo_ctrl_unlock(handle);
    if (ret < 0)
        goto err_data_mmap;
    handle->user_id = (size_t)ret;
    handle->is_shared = (handle->ctrl->data_mode == UFIFO_DATA_SHARED);
    handle->lock_type = handle->ctrl->lock;

    handle->kfifo.in = &handle->ctrl->in;
    handle->kfifo.out = &__ufifo_rx_ctrl(handle)->out;
    ret = kfifo_init(&handle->kfifo, handle->shm_size);
    if (ret < 0)
        goto err_register;
    handle->ctrl->mask = handle->kfifo.mask;

    ufifo_get_version_info(NULL, &handle->ctrl->ver);
    smp_store_release(&handle->ctrl->init_done, true);

    return 0;

err_register:
    __ufifo_ctrl_lock(handle);
    __ufifo_unregister(handle);
    __ufifo_ctrl_unlock(handle);
err_data_mmap:
    munmap(handle->shm_mem, handle->shm_size);
err_lock:
    __ufifo_lock_deinit(handle);
err_ctrl_mmap:
    munmap(handle->ctrl, handle->ctrl_size);
err_ctrl_fd:
    close(handle->ctrl_fd);
    shm_unlink(ctrl_name);
end:
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Validation                                                         */
/* ------------------------------------------------------------------ */

static int __ufifo_init_validate(const ufifo_init_t *init)
{
    if (init->opt >= UFIFO_OPT_MAX) {
        return -EINVAL;
    }

    if (init->opt == UFIFO_OPT_ALLOC) {
        if (init->alloc.max_users < 1 || init->alloc.max_users > UFIFO_MAX_NUM_USERS) {
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

/* ------------------------------------------------------------------ */
/*  Public API: open / close / destroy                                 */
/* ------------------------------------------------------------------ */

int ufifo_open(const char *name, const ufifo_init_t *init, ufifo_t **handle)
{
    int ret = 0;
    ufifo_t *fifo = NULL;
    bool is_alloc = false;
    ufifo_init_t fifo_init;

    if (name == NULL || init == NULL || handle == NULL)
        return -EINVAL;
    if (strlen(name) > UFIFO_NAME_MAX)
        return -ENAMETOOLONG;

    ret = __ufifo_init_validate(init);
    if (ret < 0)
        return ret;
    memcpy(&fifo_init, init, sizeof(ufifo_init_t));

    fifo = calloc(1, sizeof(ufifo_t));
    if (fifo == NULL)
        return -ENOMEM;
    strncpy(fifo->name, name, sizeof(fifo->name) - 1);
    ret = __ufifo_hook_init(fifo, &fifo_init.hook);
    if (ret < 0)
        goto err1;

    if (fifo_init.opt == UFIFO_OPT_ALLOC) {
        if (fifo_init.alloc.force) {
            /* force=1 performs a cold restart of both shared-memory objects. */
            char ctrl_name[UFIFO_CTRL_NAME_BUF_SIZE];
            snprintf(ctrl_name, sizeof(ctrl_name), "%s%s", name, UFIFO_CTRL_NAME_SUFFIX);
            shm_unlink(name);
            shm_unlink(ctrl_name);
            fifo->shm_fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, (S_IRUSR | S_IWUSR));
        } else {
            fifo->shm_fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, (S_IRUSR | S_IWUSR));
            if (fifo->shm_fd < 0 && errno == EEXIST) {
                fifo_init.opt = UFIFO_OPT_ATTACH;
                fifo->shm_fd = shm_open(name, O_RDWR, (S_IRUSR | S_IWUSR));
            }
        }
    } else {
        fifo->shm_fd = shm_open(name, O_RDWR, (S_IRUSR | S_IWUSR));
    }
    if (fifo->shm_fd < 0) {
        ret = -errno;
        goto err1;
    }

    if (fifo_init.opt == UFIFO_OPT_ALLOC) {
        is_alloc = true;
        if (__ufifo_init_lock(fifo->shm_fd) < 0) {
            ret = -errno;
            goto err2;
        }
        ret = __ufifo_init_from_user(fifo, &fifo_init.alloc);
        __ufifo_init_unlock(fifo->shm_fd);
        if (ret < 0)
            goto err2;
    } else {
        if (__ufifo_init_wait(fifo->shm_fd) < 0) {
            ret = -errno;
            goto err2;
        }
        __ufifo_init_unlock(fifo->shm_fd);
        ret = __ufifo_init_from_shm(fifo);
        if (ret < 0)
            goto err2;
    }

    fifo->magic = UFIFO_MAGIC;
    *handle = fifo;
    return 0;

err2:
    close(fifo->shm_fd);
    if (is_alloc)
        shm_unlink(fifo->name);
err1:
    free(fifo);
    return ret;
}

static int __ufifo_close(ufifo_t *handle, bool destroy)
{
    char ctrl_name[UFIFO_CTRL_NAME_BUF_SIZE];

    __ufifo_ctrl_lock(handle);
    __ufifo_unregister(handle);
    __ufifo_ctrl_unlock(handle);

    if (destroy) {
        __ufifo_lock_deinit(handle);
    }

    munmap(handle->shm_mem, handle->shm_size);
    close(handle->shm_fd);

    munmap(handle->ctrl, handle->ctrl_size);
    close(handle->ctrl_fd);

    if (destroy) {
        shm_unlink(handle->name);
        snprintf(ctrl_name, sizeof(ctrl_name), "%s%s", handle->name, UFIFO_CTRL_NAME_SUFFIX);
        shm_unlink(ctrl_name);
    }

    /* Best-effort invalidation to defend against double-free / stale pointer */
    handle->magic = 0;
    free(handle);
    return 0;
}

int ufifo_close(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_close(handle, false);
}

int ufifo_destroy(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_close(handle, true);
}
