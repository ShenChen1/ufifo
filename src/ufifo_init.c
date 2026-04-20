#include "ufifo_internal.h"

int __ufifo_is_shared(ufifo_t *ufifo)
{
    return ufifo->ctrl->data_mode == UFIFO_DATA_SHARED;
}

void __ufifo_reap_dead_user(ufifo_ctrl_t *ctrl, unsigned int user_id)
{
    if (READ_ONCE(&ctrl->users[user_id].active)) {
        WRITE_ONCE(&ctrl->users[user_id].active, 0);
        ctrl->num_users--;

        while (sem_trywait(&ctrl->users[user_id].bsem_rd) == 0) {
        }
    }
}

int __ufifo_register(ufifo_t *ufifo)
{
    ufifo_ctrl_t *ctrl = ufifo->ctrl;
    unsigned int i;
    pid_t mypid = getpid();

    for (i = 0; i < ctrl->max_users; i++) {
        if (!READ_ONCE(&ctrl->users[i].active)) {
            WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(ufifo->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, 1);
            ctrl->num_users++;
            return i;
        }
    }

    for (i = 0; i < ctrl->max_users; i++) {
        if (READ_ONCE(&ctrl->users[i].active) && __ufifo_is_user_dead(ufifo->ctrl_fd, i)) {
            __ufifo_reap_dead_user(ctrl, i);

            WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
            ctrl->users[i].pid = mypid;
            __ufifo_ofd_lock(ufifo->ctrl_fd, i);
            smp_store_release(&ctrl->users[i].active, 1);
            ctrl->num_users++;
            return i;
        }
    }

    return -ENOSPC;
}

static void __ufifo_unregister(ufifo_t *ufifo)
{
    ufifo_ctrl_t *ctrl = ufifo->ctrl;

    if (ufifo->user_id < ctrl->max_users && READ_ONCE(&ctrl->users[ufifo->user_id].active)) {
        smp_store_release(&ctrl->users[ufifo->user_id].active, 0);
        __ufifo_ofd_unlock(ufifo->ctrl_fd, ufifo->user_id);
        ctrl->num_users--;
    }
}

static int __ufifo_hook_init(ufifo_t *ufifo, ufifo_hook_t *hook)
{
    ufifo->hook.recsize = hook->recsize;
    ufifo->hook.rectag = hook->rectag;
    ufifo->hook.recput = hook->recput;
    ufifo->hook.recget = hook->recget;
    return 0;
}

static int __ufifo_version_check(ufifo_ctrl_t *ctrl)
{
    ufifo_version_t ver = {};
    ufifo_get_version_info(NULL, &ver);

    if (ctrl->ver.major != ver.major) {
        fprintf(stderr,
                "ufifo: version mismatch (shm=%u.%u.%u, lib=%u.%u.%u)\n",
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

static int __ufifo_init_from_shm(ufifo_t *ufifo)
{
    int ret = 0;
    struct stat st;
    char ctrl_name[NAME_MAX + 8];

    snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", ufifo->name);
    ufifo->ctrl_fd = shm_open(ctrl_name, O_RDWR, (S_IRUSR | S_IWUSR));
    if (ufifo->ctrl_fd < 0) {
        ret = -errno;
        goto end;
    }

    ret = fstat(ufifo->ctrl_fd, &st);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    ufifo->ctrl_size = st.st_size;
    ufifo->ctrl = mmap(NULL, ufifo->ctrl_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->ctrl_fd, 0);
    if (ufifo->ctrl == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    if (!smp_load_acquire(&ufifo->ctrl->init_done)) {
        ret = -EIO;
        goto err_ctrl_mmap;
    }

    ret = __ufifo_version_check(ufifo->ctrl);
    if (ret < 0)
        goto err_ctrl_mmap;

    ret = fstat(ufifo->shm_fd, &st);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    ufifo->shm_size = st.st_size;
    ufifo->shm_mem = mmap(NULL, ufifo->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->shm_fd, 0);
    if (ufifo->shm_mem == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_mmap;
    }

    __ufifo_ctrl_lock(ufifo);
    ret = __ufifo_register(ufifo);
    __ufifo_ctrl_unlock(ufifo);
    if (ret < 0)
        goto err_data_mmap;
    ufifo->user_id = (unsigned int)ret;
    ufifo->kfifo.in = &ufifo->ctrl->in;
    ufifo->kfifo.mask = &ufifo->ctrl->mask;
    ufifo->bsem_wr = &ufifo->ctrl->bsem_wr;
    if (__ufifo_is_shared(ufifo)) {
        WRITE_ONCE(&ufifo->ctrl->users[ufifo->user_id].out, READ_ONCE(&ufifo->ctrl->in));
        ufifo->kfifo.out = &ufifo->ctrl->users[ufifo->user_id].out;
        ufifo->bsem_rd = &ufifo->ctrl->users[ufifo->user_id].bsem_rd;
    } else {
        ufifo->kfifo.out = &ufifo->ctrl->users[0].out;
        ufifo->bsem_rd = &ufifo->ctrl->users[0].bsem_rd;
    }

    return 0;

err_data_mmap:
    munmap(ufifo->shm_mem, ufifo->shm_size);
err_ctrl_mmap:
    munmap(ufifo->ctrl, ufifo->ctrl_size);
err_ctrl_fd:
    close(ufifo->ctrl_fd);
end:
    return ret;
}

static int __ufifo_init_from_user(ufifo_t *ufifo, ufifo_alloc_t *alloc)
{
    int ret = 0;
    unsigned int i;
    char ctrl_name[NAME_MAX + 8];

    if (!alloc->size)
        return -EINVAL;

    snprintf(ctrl_name, sizeof(ctrl_name), "%s_ctrl", ufifo->name);
    ufifo->ctrl_size = sizeof(ufifo_ctrl_t) + alloc->max_users * sizeof(ufifo_sub_ctrl_t);
    ufifo->ctrl_fd = shm_open(ctrl_name, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR));
    if (ufifo->ctrl_fd < 0) {
        ret = -errno;
        goto end;
    }

    ret = ftruncate(ufifo->ctrl_fd, ufifo->ctrl_size);
    if (ret < 0) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    ufifo->ctrl = mmap(NULL, ufifo->ctrl_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->ctrl_fd, 0);
    if (ufifo->ctrl == MAP_FAILED) {
        ret = -errno;
        goto err_ctrl_fd;
    }

    WRITE_ONCE(&ufifo->ctrl->init_done, 0);

    ret = __ufifo_lock_init(ufifo, alloc->lock);
    if (ret < 0)
        goto err_ctrl_mmap;

    ufifo->ctrl->data_mode = alloc->data_mode;
    ufifo->ctrl->max_users = alloc->max_users;
    ufifo->ctrl->num_users = 0;
    for (i = 0; i < alloc->max_users; i++) {
        ufifo->ctrl->users[i].active = 0;
        __ufifo_bsem_init(&ufifo->ctrl->users[i].bsem_rd, 0);
    }

    ufifo->shm_size = roundup_pow_of_two(alloc->size);
    ret = ftruncate(ufifo->shm_fd, ufifo->shm_size);
    if (ret < 0) {
        ret = -errno;
        goto err_lock;
    }

    ufifo->shm_mem = mmap(NULL, ufifo->shm_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ufifo->shm_fd, 0);
    if (ufifo->shm_mem == MAP_FAILED) {
        ret = -errno;
        goto err_lock;
    }

    __ufifo_ctrl_lock(ufifo);
    ret = __ufifo_register(ufifo);
    __ufifo_ctrl_unlock(ufifo);
    if (ret < 0)
        goto err_data_mmap;
    ufifo->user_id = (unsigned int)ret;

    ufifo->kfifo.in = &ufifo->ctrl->in;
    ufifo->kfifo.out = &ufifo->ctrl->users[ufifo->user_id].out;
    ufifo->kfifo.mask = &ufifo->ctrl->mask;
    ret = kfifo_init(&ufifo->kfifo, ufifo->shm_size);
    if (ret < 0)
        goto err_register;
    ufifo->bsem_wr = &ufifo->ctrl->bsem_wr;
    __ufifo_bsem_init(ufifo->bsem_wr, 0);
    ufifo->bsem_rd = &ufifo->ctrl->users[ufifo->user_id].bsem_rd;

    ufifo_get_version_info(NULL, &ufifo->ctrl->ver);
    smp_store_release(&ufifo->ctrl->init_done, 1);

    return 0;

err_register:
    __ufifo_ctrl_lock(ufifo);
    __ufifo_unregister(ufifo);
    __ufifo_ctrl_unlock(ufifo);
err_data_mmap:
    munmap(ufifo->shm_mem, ufifo->shm_size);
err_lock:
    __ufifo_lock_deinit(ufifo);
err_ctrl_mmap:
    munmap(ufifo->ctrl, ufifo->ctrl_size);
err_ctrl_fd:
    close(ufifo->ctrl_fd);
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

int ufifo_open(char *name, ufifo_init_t *init, ufifo_t **handle)
{
    int ret = 0;
    ufifo_t *ufifo = NULL;
    int is_alloc = 0;

    if (name == NULL || init == NULL || handle == NULL)
        return -EINVAL;

    ret = __ufifo_init_validate(init);
    if (ret < 0)
        return ret;

    ufifo = calloc(1, sizeof(ufifo_t));
    if (ufifo == NULL)
        return -ENOMEM;
    ufifo->rx_efd = -1;
    ufifo->tx_efd = -1;

    strncpy(ufifo->name, name, sizeof(ufifo->name) - 1);
    ret = __ufifo_hook_init(ufifo, &init->hook);
    if (ret < 0)
        goto err1;

    if (init->opt == UFIFO_OPT_ALLOC) {
        if (init->alloc.force) {
            ufifo->shm_fd = shm_open(name, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR));
        } else {
            ufifo->shm_fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, (S_IRUSR | S_IWUSR));
            if (ufifo->shm_fd < 0 && errno == EEXIST) {
                init->opt = UFIFO_OPT_ATTACH;
                ufifo->shm_fd = shm_open(name, O_RDWR, (S_IRUSR | S_IWUSR));
            }
        }
    } else {
        ufifo->shm_fd = shm_open(name, O_RDWR, (S_IRUSR | S_IWUSR));
    }
    if (ufifo->shm_fd < 0) {
        ret = -errno;
        goto err1;
    }

    if (init->opt == UFIFO_OPT_ALLOC) {
        is_alloc = 1;
        if (__ufifo_init_lock(ufifo->shm_fd) < 0) {
            ret = -errno;
            goto err2;
        }
        ret = __ufifo_init_from_user(ufifo, &init->alloc);
        __ufifo_init_unlock(ufifo->shm_fd);
        if (ret < 0)
            goto err2;
    } else {
        if (__ufifo_init_wait(ufifo->shm_fd) < 0) {
            ret = -errno;
            goto err2;
        }
        __ufifo_init_unlock(ufifo->shm_fd);
        ret = __ufifo_init_from_shm(ufifo);
        if (ret < 0)
            goto err2;
    }

    ufifo->magic = UFIFO_MAGIC;
    *handle = ufifo;
    return 0;

err2:
    close(ufifo->shm_fd);
    if (is_alloc)
        shm_unlink(ufifo->name);
err1:
    free(ufifo);
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
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_close(handle, 0);
}

int ufifo_destroy(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_close(handle, 1);
}
