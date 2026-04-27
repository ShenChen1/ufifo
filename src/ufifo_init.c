#include "ufifo_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log2.h"
#include "utils.h"

int __ufifo_is_shared(ufifo_t *handle)
{
    return handle->ctrl->data_mode == UFIFO_DATA_SHARED;
}

void __ufifo_reap_dead_user(ufifo_t *handle, unsigned int user_id)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;

    if (READ_ONCE(&ctrl->users[user_id].active)) {
        WRITE_ONCE(&ctrl->users[user_id].active, 0);
        ctrl->num_users--;

        while (sem_trywait(&ctrl->users[user_id].bsem_rd) == 0) {
        }
    }
}

int __ufifo_register(ufifo_t *handle)
{
    ufifo_ctrl_t *ctrl = handle->ctrl;
    unsigned int i;
    pid_t mypid = getpid();

    for (i = 0; i < ctrl->max_users; i++) {
        if (!READ_ONCE(&ctrl->users[i].active)) {
            WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(handle->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, 1);
            ctrl->num_users++;
            return i;
        }
    }

    for (i = 0; i < ctrl->max_users; i++) {
        if (READ_ONCE(&ctrl->users[i].active) && __ufifo_is_user_dead(handle->ctrl_fd, i)) {
            __ufifo_reap_dead_user(handle, i);

            WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(handle->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, 1);
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
        smp_store_release(&ctrl->users[handle->user_id].active, 0);
        __ufifo_ofd_unlock(handle->ctrl_fd, handle->user_id);
        ctrl->num_users--;
    }
}

static int __ufifo_hook_init(ufifo_t *handle, ufifo_hook_t *hook)
{
    handle->hook.recsize = hook->recsize;
    handle->hook.rectag = hook->rectag;
    handle->hook.recput = hook->recput;
    handle->hook.recget = hook->recget;
    return 0;
}

static int __ufifo_version_check(ufifo_ctrl_t *ctrl)
{
    ufifo_version_t ver = {};
    ufifo_get_version_info(NULL, &ver);

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

static int __ufifo_init_from_shm(ufifo_t *handle)
{
    int ret = 0;
    struct stat st;
    char ctrl_name[NAME_MAX + 8];

    snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", handle->name);
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

    if (!smp_load_acquire(&handle->ctrl->init_done)) {
        ret = -EIO;
        goto err_ctrl_mmap;
    }

    ret = __ufifo_version_check(handle->ctrl);
    if (ret < 0)
        goto err_ctrl_mmap;

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
    handle->user_id = (unsigned int)ret;
    handle->kfifo.in = &handle->ctrl->in;
    handle->kfifo.mask = &handle->ctrl->mask;
    handle->bsem_wr = &handle->ctrl->bsem_wr;
    if (__ufifo_is_shared(handle)) {
        WRITE_ONCE(&handle->ctrl->users[handle->user_id].out, READ_ONCE(&handle->ctrl->in));
        handle->kfifo.out = &handle->ctrl->users[handle->user_id].out;
        handle->bsem_rd = &handle->ctrl->users[handle->user_id].bsem_rd;
    } else {
        handle->kfifo.out = &handle->ctrl->users[0].out;
        handle->bsem_rd = &handle->ctrl->users[0].bsem_rd;
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

static int __ufifo_init_from_user(ufifo_t *handle, ufifo_alloc_t *alloc)
{
    int ret = 0;
    unsigned int i;
    char ctrl_name[NAME_MAX + 8];

    if (!alloc->size)
        return -EINVAL;

    snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", handle->name);
    handle->ctrl_size = sizeof(ufifo_ctrl_t) + alloc->max_users * sizeof(ufifo_sub_ctrl_t);
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

    WRITE_ONCE(&handle->ctrl->init_done, 0);

    ret = __ufifo_lock_init(handle, alloc->lock);
    if (ret < 0)
        goto err_ctrl_mmap;

    handle->ctrl->data_mode = alloc->data_mode;
    handle->ctrl->max_users = alloc->max_users;
    handle->ctrl->num_users = 0;
    for (i = 0; i < alloc->max_users; i++) {
        handle->ctrl->users[i].active = 0;
        __ufifo_bsem_init(&handle->ctrl->users[i].bsem_rd, 0);
    }

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
    handle->user_id = (unsigned int)ret;

    handle->kfifo.in = &handle->ctrl->in;
    handle->kfifo.out = &handle->ctrl->users[handle->user_id].out;
    handle->kfifo.mask = &handle->ctrl->mask;
    ret = kfifo_init(&handle->kfifo, handle->shm_size);
    if (ret < 0)
        goto err_register;
    handle->bsem_wr = &handle->ctrl->bsem_wr;
    __ufifo_bsem_init(handle->bsem_wr, 0);
    handle->bsem_rd = &handle->ctrl->users[handle->user_id].bsem_rd;

    ufifo_get_version_info(NULL, &handle->ctrl->ver);
    smp_store_release(&handle->ctrl->init_done, 1);

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

static int __ufifo_init_validate(const ufifo_init_t *init)
{
    if (init->opt >= UFIFO_OPT_MAX) {
        return -EINVAL;
    }

    if (init->opt == UFIFO_OPT_ALLOC) {
        if (init->alloc.max_users < 1) {
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

int ufifo_open(const char *name, const ufifo_init_t *init, ufifo_t **handle)
{
    int ret = 0;
    ufifo_t *fifo = NULL;
    int is_alloc = 0;
    ufifo_init_t fifo_init;

    if (name == NULL || init == NULL || handle == NULL)
        return -EINVAL;

    ret = __ufifo_init_validate(init);
    if (ret < 0)
        return ret;
    memcpy(&fifo_init, init, sizeof(ufifo_init_t));

    fifo = calloc(1, sizeof(ufifo_t));
    if (fifo == NULL)
        return -ENOMEM;
    fifo->rx_efd = -1;
    fifo->tx_efd = -1;

    strncpy(fifo->name, name, sizeof(fifo->name) - 1);
    ret = __ufifo_hook_init(fifo, &fifo_init.hook);
    if (ret < 0)
        goto err1;

    if (fifo_init.opt == UFIFO_OPT_ALLOC) {
        if (fifo_init.alloc.force) {
            fifo->shm_fd = shm_open(name, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR));
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
        is_alloc = 1;
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

static int __ufifo_close(ufifo_t *handle, int destroy)
{
    char ctrl_name[NAME_MAX + 8];

    if (handle->rx_efd >= 0) {
        smp_store_release(&handle->ctrl->users[handle->user_id].efd_rx_flag, 0);
        close(handle->rx_efd);
        handle->rx_efd = -1;
    }
    if (handle->tx_efd >= 0) {
        smp_store_release(&handle->ctrl->efd_tx_flag, 0);
        close(handle->tx_efd);
        handle->tx_efd = -1;
    }
    __ufifo_ctrl_lock(handle);
    __ufifo_unregister(handle);
    __ufifo_ctrl_unlock(handle);
    if (destroy) {
        unsigned int i;
        __ufifo_lock_deinit(handle);
        __ufifo_bsem_deinit(handle->bsem_wr);
        for (i = 0; i < handle->ctrl->max_users; i++) {
            __ufifo_bsem_deinit(&handle->ctrl->users[i].bsem_rd);
        }
    }

    munmap(handle->shm_mem, handle->shm_size);
    close(handle->shm_fd);

    munmap(handle->ctrl, handle->ctrl_size);
    close(handle->ctrl_fd);

    if (destroy) {
        shm_unlink(handle->name);
        snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", handle->name);
        shm_unlink(ctrl_name);
    }
    free(handle);
    return 0;
}

int ufifo_close(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_close(handle, 0);
}

int ufifo_destroy(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_close(handle, 1);
}
