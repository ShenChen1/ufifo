#include "ufifo_internal.h"
#include <errno.h>

#include "utils.h"

static unsigned int __ufifo_min_out(ufifo_t *handle)
{
    unsigned int in_val = smp_load_acquire(handle->kfifo.in);
    unsigned int max_distance = 0;
    unsigned int min_out = in_val;
    unsigned int i;

    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (smp_load_acquire(&handle->ctrl->users[i].active)) {
            unsigned int u_out = smp_load_acquire(&handle->ctrl->users[i].out);
            int distance = (int)(in_val - u_out);
            if (distance > (int)max_distance) {
                max_distance = (unsigned int)distance;
                min_out = u_out;
            }
        }
    }

    return min_out;
}

void __ufifo_update_cached_min_out(ufifo_t *handle)
{
    unsigned int min_o = __ufifo_min_out(handle);
    unsigned int cur_cached = smp_load_acquire(&handle->ctrl->cached_min_out);

    while ((int)(min_o - cur_cached) > 0) {
        if (atomic_cmpxchg(&handle->ctrl->cached_min_out, &cur_cached, min_o)) {
            break;
        }
    }
}

unsigned int __ufifo_unused_len(ufifo_t *handle)
{
    unsigned int out;
    unsigned int len;

    if (__ufifo_is_shared(handle)) {
        out = smp_load_acquire(&handle->ctrl->cached_min_out);
    } else {
        out = smp_load_acquire(handle->kfifo.out);
    }

    len = READ_ONCE(handle->kfifo.in) - out;
    return *handle->kfifo.mask + 1 - len;
}

static unsigned int __ufifo_peek_len(ufifo_t *handle, unsigned int offset, unsigned int in_val)
{
    unsigned int len = in_val == offset ? 0 : 1;
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
    UFIFO_CHECK_HANDLE(handle, 0);
    return *handle->kfifo.mask + 1;
}

void ufifo_reset(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle);

    __ufifo_data_lock(handle);
    smp_store_release(handle->kfifo.in, 0);
    smp_store_release(handle->kfifo.out, 0);
    if (__ufifo_is_shared(handle)) {
        for (unsigned int i = 0; i < handle->ctrl->max_users; i++) {
            if (smp_load_acquire(&handle->ctrl->users[i].active)) {
                smp_store_release(&handle->ctrl->users[i].out, 0);
            }
        }
        smp_store_release(&handle->ctrl->cached_min_out, 0);
    }
    __ufifo_data_unlock(handle);
}

unsigned int ufifo_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE(handle, 0);

    __ufifo_data_lock(handle);
    len = READ_ONCE(handle->kfifo.in) - READ_ONCE(handle->kfifo.out);
    __ufifo_data_unlock(handle);

    return len;
}

void ufifo_skip(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle);

    __ufifo_data_lock(handle);
    unsigned int out = READ_ONCE(handle->kfifo.out);
    unsigned int new_out = out + __ufifo_peek_len(handle, out, READ_ONCE(handle->kfifo.in));
    smp_store_release(handle->kfifo.out, new_out);
    if (__ufifo_is_shared(handle)) {
        if (out == smp_load_acquire(&handle->ctrl->cached_min_out)) {
            __ufifo_update_cached_min_out(handle);
        }
    }
    __ufifo_efd_notify(handle->efd_wr, &handle->ctrl->tx_waiters, &handle->ctrl->epoll_tx_armed);
    __ufifo_data_unlock(handle);
}

unsigned int ufifo_peek_len(ufifo_t *handle)
{
    unsigned int len;
    UFIFO_CHECK_HANDLE(handle, 0);

    __ufifo_data_lock(handle);
    unsigned int out_val = READ_ONCE(handle->kfifo.out);
    unsigned int in_val = smp_load_acquire(handle->kfifo.in);
    len = __ufifo_peek_len(handle, out_val, in_val);
    __ufifo_data_unlock(handle);

    return len;
}

static int __ufifo_try_reap_dead_readers(ufifo_t *handle)
{
    int cleaned = 0;
    unsigned int i;

    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (i == handle->user_id)
            continue;
        if (smp_load_acquire(&handle->ctrl->users[i].active)) {
            if (__ufifo_is_user_dead(handle->ctrl_fd, i)) {
                __ufifo_ctrl_lock(handle);
                if (READ_ONCE(&handle->ctrl->users[i].active)) {
                    __ufifo_reap_dead_user(handle, i);
                    cleaned = 1;
                }
                __ufifo_ctrl_unlock(handle);
            }
        }
    }

    if (cleaned) {
        __ufifo_update_cached_min_out(handle);
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
        if (len >= size)
            break;

        /* Slow path: Check if space is constrained by dead shared readers or stale cache */
        if (__ufifo_is_shared(handle)) {
            __ufifo_update_cached_min_out(handle);
            if (__ufifo_try_reap_dead_readers(handle)) {
                continue; /* Re-evaluate len after reaping */
            }
            len = __ufifo_unused_len(handle);
            if (len >= size)
                break;
        }

        if (millisec == 0) {
            ret = -1;
        } else if (millisec == -1) {
            ret = __ufifo_efd_wait(handle->efd_wr, handle, &handle->ctrl->tx_waiters);
        } else {
            ret = __ufifo_efd_timedwait(handle->efd_wr, handle, millisec, &handle->ctrl->tx_waiters);
            millisec = 0;
        }
        if (ret) {
            len = 0;
            goto end;
        }
    }
    if (unlikely(handle->hook.recput)) {
        unsigned int in = READ_ONCE(handle->kfifo.in);
        len = *handle->kfifo.mask & in;
        len = handle->hook.recput(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (size != len) {
            len = 0;
            goto end;
        }
        smp_store_release(handle->kfifo.in, in + len);
    } else {
        len = kfifo_in(&handle->kfifo, handle->shm_mem, buf, size);
    }

    if (__ufifo_is_shared(handle)) {
        for (unsigned int i = 0; i < handle->ctrl->max_users; i++) {
            if (smp_load_acquire(&handle->ctrl->users[i].active))
                __ufifo_efd_notify(
                    handle->efd_rd_all[i],
                    &handle->ctrl->users[i].rx_waiters,
                    &handle->ctrl->users[i].epoll_armed);
        }
    } else {
        __ufifo_efd_notify(
            handle->efd_rd_all[0],
            &handle->ctrl->users[0].rx_waiters,
            &handle->ctrl->users[0].epoll_armed);
    }

end:
    __ufifo_data_unlock(handle);

    return len;
}

unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_put(handle, buf, size, 0);
}

unsigned int ufifo_put_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_put(handle, buf, size, -1);
}

unsigned int ufifo_put_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_put(handle, buf, size, millisec);
}

static unsigned int __ufifo_get(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;
    unsigned int user_id = __ufifo_is_shared(handle) ? handle->user_id : 0;

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out), READ_ONCE(handle->kfifo.in));
        if (len == 0) {
            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_efd_wait(handle->efd_rd, handle, &handle->ctrl->users[user_id].rx_waiters);
            } else {
                ret = __ufifo_efd_timedwait(handle->efd_rd, handle, millisec, &handle->ctrl->users[user_id].rx_waiters);
                millisec = 0;
            }
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }

    unsigned int old_out = READ_ONCE(handle->kfifo.out);
    if (unlikely(handle->hook.recget)) {
        unsigned int out = old_out;
        len = *handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        smp_store_release(handle->kfifo.out, out + len);
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out(&handle->kfifo, handle->shm_mem, buf, size);
    }

    if (__ufifo_is_shared(handle)) {
        if (old_out == smp_load_acquire(&handle->ctrl->cached_min_out)) {
            __ufifo_update_cached_min_out(handle);
        }
    }

    __ufifo_efd_notify(handle->efd_wr, &handle->ctrl->tx_waiters, &handle->ctrl->epoll_tx_armed);

end:
    __ufifo_data_unlock(handle);

    return len;
}

unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_get(handle, buf, size, 0);
}

unsigned int ufifo_get_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_get(handle, buf, size, -1);
}

unsigned int ufifo_get_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_get(handle, buf, size, millisec);
}

static unsigned int __ufifo_peek(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    int ret;
    unsigned int len;
    unsigned int user_id = __ufifo_is_shared(handle) ? handle->user_id : 0;

    __ufifo_data_lock(handle);
    while (1) {
        len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out), READ_ONCE(handle->kfifo.in));
        if (len == 0) {
            if (millisec == 0) {
                ret = -1;
            } else if (millisec == -1) {
                ret = __ufifo_efd_wait(handle->efd_rd, handle, &handle->ctrl->users[user_id].rx_waiters);
            } else {
                ret = __ufifo_efd_timedwait(handle->efd_rd, handle, millisec, &handle->ctrl->users[user_id].rx_waiters);
                millisec = 0;
            }
            if (ret) {
                goto end;
            }
        } else {
            break;
        }
    }

    if (unlikely(handle->hook.recget)) {
        unsigned int out = READ_ONCE(handle->kfifo.out);
        len = *handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, *handle->kfifo.mask - len + 1, handle->shm_mem, buf);
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out_peek(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_efd_notify(handle->efd_wr, &handle->ctrl->tx_waiters, &handle->ctrl->epoll_tx_armed);
end:
    __ufifo_data_unlock(handle);

    return len;
}

unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_peek(handle, buf, size, 0);
}

unsigned int ufifo_peek_block(ufifo_t *handle, void *buf, unsigned int size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_peek(handle, buf, size, -1);
}

unsigned int ufifo_peek_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_peek(handle, buf, size, millisec);
}

int ufifo_oldest(ufifo_t *handle, unsigned int tag)
{
    int ret = 0;
    unsigned int len, tmp, old_out;
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
    unsigned int in_val = READ_ONCE(handle->kfifo.in);
    while (tmp != in_val) {
        len = __ufifo_peek_len(handle, tmp, in_val);
        if (len == 0)
            break;
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            ret = 0;
            goto found;
        }
        tmp += len;
    }
    ret = -ESPIPE;
found:
    old_out = READ_ONCE(handle->kfifo.out);
    smp_store_release(handle->kfifo.out, tmp);
    if (__ufifo_is_shared(handle)) {
        if (old_out == smp_load_acquire(&handle->ctrl->cached_min_out)) {
            __ufifo_update_cached_min_out(handle);
        }
    }
    __ufifo_efd_notify(handle->efd_wr, &handle->ctrl->tx_waiters, &handle->ctrl->epoll_tx_armed);
    __ufifo_data_unlock(handle);

    return ret;
}

int ufifo_newest(ufifo_t *handle, unsigned int tag)
{
    int ret = 0;
    bool found = false;
    unsigned int len, tmp;
    unsigned int final = 0;
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
    unsigned int in_val = READ_ONCE(handle->kfifo.in);
    while (tmp != in_val) {
        len = __ufifo_peek_len(handle, tmp, in_val);
        if (len == 0)
            break;
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            found = true;
            final = tmp;
        }
        tmp += len;
    }
    if (found) {
        tmp = final;
        ret = 0;
    } else {
        ret = -ESPIPE;
    }
    unsigned int old_out = READ_ONCE(handle->kfifo.out);
    smp_store_release(handle->kfifo.out, tmp);
    if (__ufifo_is_shared(handle)) {
        if (old_out == smp_load_acquire(&handle->ctrl->cached_min_out)) {
            __ufifo_update_cached_min_out(handle);
        }
    }
    __ufifo_efd_notify(handle->efd_wr, &handle->ctrl->tx_waiters, &handle->ctrl->epoll_tx_armed);
    __ufifo_data_unlock(handle);

    return ret;
}
