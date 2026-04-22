#include "ufifo_internal.h"
#include <errno.h>

#include "utils.h"

static unsigned int __ufifo_min_out(ufifo_t *handle)
{
    unsigned int in_val = READ_ONCE(handle->kfifo.in);
    unsigned int max_distance = 0;
    unsigned int min_out = in_val;
    unsigned int i;

    ufifo_for_each_active_user(handle, i) {
        unsigned int u_out = smp_load_acquire(&handle->ctrl->users[i].out);
        unsigned int distance = in_val - u_out;
        if (distance > max_distance) {
            max_distance = distance;
            min_out = u_out;
        }
    }

    return min_out;
}

static unsigned int __ufifo_unused_len(ufifo_t *handle)
{
    unsigned int out;
    unsigned int len;

    if (__ufifo_is_shared(handle)) {
        out = __ufifo_min_out(handle);
    } else {
        out = smp_load_acquire(handle->kfifo.out);
    }

    len = READ_ONCE(handle->kfifo.in) - out;
    return *handle->kfifo.mask + 1 - len;
}

static unsigned int __ufifo_peek_len(ufifo_t *handle, unsigned int offset)
{
    unsigned int len = smp_load_acquire(handle->kfifo.in) == offset ? 0 : 1;

    if (len && handle->hook.recsize) {
        offset &= *handle->kfifo.mask;
        len = handle->hook.recsize(handle->shm_mem + offset, *handle->kfifo.mask - offset + 1, handle->shm_mem);
    }

    return len;
}

static unsigned int __ufifo_peek_tag(ufifo_t *handle, unsigned int offset)
{
    unsigned int ret = 0;

    if (handle->hook.rectag) {
        offset &= *handle->kfifo.mask;
        ret = handle->hook.rectag(handle->shm_mem + offset, *handle->kfifo.mask - offset + 1, handle->shm_mem);
    }

    return ret;
}

unsigned int ufifo_size(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return *handle->kfifo.mask + 1;
}

void ufifo_reset(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    WRITE_ONCE(handle->kfifo.in, 0);
    WRITE_ONCE(handle->kfifo.out, 0);
    __ufifo_data_unlock(handle);
}

unsigned int ufifo_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    len = READ_ONCE(handle->kfifo.in) - READ_ONCE(handle->kfifo.out);
    __ufifo_data_unlock(handle);

    return len;
}

void ufifo_skip(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    unsigned int out = READ_ONCE(handle->kfifo.out);
    smp_store_release(handle->kfifo.out, out + __ufifo_peek_len(handle, out));
    __ufifo_data_unlock(handle);
}

unsigned int ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out));
    __ufifo_data_unlock(handle);

    return len;
}

static int __ufifo_try_reap_dead_readers(ufifo_t *handle)
{
    int cleaned = 0;
    unsigned int i;

    ufifo_for_each_active_user(handle, i) {
        if (i == handle->user_id)
            continue;
        if (__ufifo_is_user_dead(handle->ctrl_fd, i)) {
            __ufifo_ctrl_lock(handle);
            if (READ_ONCE(&handle->ctrl->users[i].active)) {
                __ufifo_reap_dead_user(handle, i);
                cleaned = 1;
            }
            __ufifo_ctrl_unlock(handle);
        }
    }

    return cleaned;
}

static unsigned int __ufifo_put(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_unused_len(handle);
        if (len < size) {
            /* Slow path: Check if space is constrained by dead shared readers */
            if (__ufifo_is_shared(handle)) {
                if (__ufifo_try_reap_dead_readers(handle)) {
                    continue; /* Re-evaluate len */
                }
            }

            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_bsem_wait(handle->bsem_wr, handle);
            } else {
                ret = __ufifo_bsem_timedwait(handle->bsem_wr, handle, millisec);
                millisec = 0;
            }
            if (ret) {
                len = 0;
                goto end;
            }
        } else {
            break;
        }
    }
    if (handle->hook.recput) {
        unsigned int in = READ_ONCE(handle->kfifo.in);
        len = *handle->kfifo.mask & in;
        len = handle->hook.recput(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        assert(size == len);
        smp_store_release(handle->kfifo.in, in + len);
    } else {
        len = kfifo_in(&handle->kfifo, handle->shm_mem, buf, size);
    }

    if (__ufifo_is_shared(handle)) {
        unsigned int i;
        ufifo_for_each_active_user(handle, i) {
            __ufifo_bsem_post(&handle->ctrl->users[i].bsem_rd);
        }
    } else {
        __ufifo_bsem_post(handle->bsem_rd);
    }
    __ufifo_efd_notify_rx(handle);

end:
    __ufifo_data_unlock(handle);

    return len;
}

unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_put(handle, buf, size, 0);
}

unsigned int ufifo_put_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_put(handle, buf, size, -1);
}

unsigned int ufifo_put_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_put(handle, buf, size, millisec);
}

static unsigned int __ufifo_get(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out));
        if (len == 0) {
            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_bsem_wait(handle->bsem_rd, handle);
            } else {
                ret = __ufifo_bsem_timedwait(handle->bsem_rd, handle, millisec);
                millisec = 0;
            }
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }

    if (handle->hook.recget) {
        unsigned int out = READ_ONCE(handle->kfifo.out);
        len = *handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        smp_store_release(handle->kfifo.out, out + len);
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_bsem_post(handle->bsem_wr);
    __ufifo_efd_notify_tx(handle);

end:
    __ufifo_data_unlock(handle);

    return len;
}

unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get(handle, buf, size, 0);
}

unsigned int ufifo_get_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get(handle, buf, size, -1);
}

unsigned int ufifo_get_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get(handle, buf, size, millisec);
}

static unsigned int __ufifo_peek(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out));
        if (len == 0) {
            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_bsem_wait(handle->bsem_rd, handle);
            } else {
                ret = __ufifo_bsem_timedwait(handle->bsem_rd, handle, millisec);
                millisec = 0;
            }
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }

    if (handle->hook.recget) {
        unsigned int out = READ_ONCE(handle->kfifo.out);
        len = *handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out_peek(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_bsem_post(handle->bsem_wr);
end:
    __ufifo_data_unlock(handle);

    return len;
}

unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_peek(handle, buf, size, 0);
}

unsigned int ufifo_peek_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_peek(handle, buf, size, -1);
}

unsigned int ufifo_peek_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_peek(handle, buf, size, millisec);
}

int ufifo_oldest(ufifo_t *handle, unsigned int tag)
{
    int ret = 0;
    unsigned int len, tmp;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
    while (1) {
        len = __ufifo_peek_len(handle, tmp);
        if (!len) {
            ret = -ESPIPE;
            break;
        }
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            ret = 0;
            break;
        }
        tmp += len;
    }
    smp_store_release(handle->kfifo.out, tmp);
    __ufifo_data_unlock(handle);

    return ret;
}

int ufifo_newest(ufifo_t *handle, unsigned int tag)
{
    int ret = 0;
    bool found = false;
    unsigned int len, tmp;
    unsigned int final = 0;
    UFIFO_CHECK_HANDLE_FUNC(handle);

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
    while (1) {
        len = __ufifo_peek_len(handle, tmp);
        if (!len) {
            tmp = found ? final : tmp;
            ret = found ? 0 : -ESPIPE;
            break;
        }
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            found = true;
            final = tmp;
        }
        tmp += len;
    }
    smp_store_release(handle->kfifo.out, tmp);
    __ufifo_data_unlock(handle);

    return ret;
}
