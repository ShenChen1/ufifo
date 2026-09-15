#include "ufifo_internal.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#include "utils.h"

typedef enum {
    UFIFO_WAIT_NONE = 0,
    UFIFO_WAIT_BLOCK = 1,
    UFIFO_WAIT_TIMED = 2,
} ufifo_wait_type_e;

static inline void __ufifo_calc_deadline(long millisec, struct timespec *deadline)
{
    if (millisec < 0) {
        millisec = 0;
    }
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += millisec / 1000;
    deadline->tv_nsec += (millisec % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec += 1;
        deadline->tv_nsec -= 1000000000L;
    }
}

static inline long __ufifo_remaining_ms(const struct timespec *deadline)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long remaining = (deadline->tv_sec - now.tv_sec) * 1000L + (deadline->tv_nsec - now.tv_nsec) / 1000000L;
    return remaining > 0 ? remaining : 0;
}

static size_t __ufifo_min_out(ufifo_t *handle)
{
    size_t in_val = smp_load_acquire(handle->kfifo.in);
    ssize_t max_distance = 0;
    size_t min_out = in_val;
    size_t i;

    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (smp_load_acquire(&handle->ctrl->users[i].active)) {
            size_t u_out = smp_load_acquire(&handle->ctrl->users[i].out);
            ssize_t distance = (ssize_t)(in_val - u_out);
            if (distance > max_distance) {
                max_distance = distance;
                min_out = u_out;
            }
        }
    }

    return min_out;
}

void __ufifo_update_cached_min_out(ufifo_t *handle)
{
    size_t min_o = __ufifo_min_out(handle);
    size_t cur_cached = smp_load_acquire(&handle->ctrl->cached_min_out);

    while ((ssize_t)(min_o - cur_cached) > 0) {
        if (atomic_cmpxchg(&handle->ctrl->cached_min_out, &cur_cached, min_o)) {
            break;
        }
    }
}

size_t __ufifo_unused_len(ufifo_t *handle)
{
    size_t out;
    size_t len;

    if (__ufifo_is_shared(handle)) {
        out = smp_load_acquire(&handle->ctrl->cached_min_out);
    } else {
        out = smp_load_acquire(handle->kfifo.out);
    }

    len = READ_ONCE(handle->kfifo.in) - out;
    return handle->kfifo.mask + 1 - len;
}

static size_t __ufifo_peek_len(ufifo_t *handle, size_t offset, size_t in_val)
{
    size_t len = (in_val == offset) ? 0 : 1;
    if (len && handle->hook.recsize) {
        offset &= handle->kfifo.mask;
        len = handle->hook.recsize(handle->shm_mem + offset, handle->kfifo.mask - offset + 1, handle->shm_mem);
    }
    return len;
}

static size_t __ufifo_peek_tag(ufifo_t *handle, size_t offset)
{
    size_t ret = 0;

    if (handle->hook.rectag) {
        offset &= handle->kfifo.mask;
        ret = handle->hook.rectag(handle->shm_mem + offset, handle->kfifo.mask - offset + 1, handle->shm_mem);
    }

    return ret;
}

size_t ufifo_size(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return handle->kfifo.mask + 1;
}

void ufifo_reset(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle);

    __ufifo_data_lock(handle);
    smp_store_release(handle->kfifo.in, 0);
    smp_store_release(handle->kfifo.out, 0);
    if (__ufifo_is_shared(handle)) {
        for (size_t i = 0; i < handle->ctrl->max_users; i++) {
            if (smp_load_acquire(&handle->ctrl->users[i].active)) {
                smp_store_release(&handle->ctrl->users[i].out, 0);
            }
        }
        smp_store_release(&handle->ctrl->cached_min_out, 0);
    }
    __ufifo_notify_writers(handle);
    __ufifo_data_unlock(handle);
}

size_t ufifo_len(ufifo_t *handle)
{
    size_t len;
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
    size_t out = READ_ONCE(handle->kfifo.out);
    size_t new_out = out + __ufifo_peek_len(handle, out, READ_ONCE(handle->kfifo.in));
    smp_store_release(handle->kfifo.out, new_out);
    if (__ufifo_is_shared(handle)) {
        if (out == smp_load_acquire(&handle->ctrl->cached_min_out)) {
            __ufifo_update_cached_min_out(handle);
        }
    }
    __ufifo_notify_writers(handle);
    __ufifo_data_unlock(handle);
}

size_t ufifo_peek_len(ufifo_t *handle)
{
    size_t len;
    UFIFO_CHECK_HANDLE(handle, 0);

    __ufifo_data_lock(handle);
    size_t out_val = READ_ONCE(handle->kfifo.out);
    size_t in_val = smp_load_acquire(handle->kfifo.in);
    len = __ufifo_peek_len(handle, out_val, in_val);
    __ufifo_data_unlock(handle);

    return len;
}

static int __ufifo_try_reap_dead_readers(ufifo_t *handle)
{
    int cleaned = 0;
    size_t i;

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
        __ufifo_notify_writers(handle);
    }

    return cleaned;
}

static inline int
__ufifo_wait_for_space(ufifo_t *handle, size_t size, ufifo_wait_type_e wait_type, long millisec, size_t *out_len)
{
    int ret = 0;
    size_t len;
    struct timespec deadline;

    if (wait_type == UFIFO_WAIT_TIMED) {
        __ufifo_calc_deadline(millisec, &deadline);
    }

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

        if (wait_type == UFIFO_WAIT_NONE) {
            errno = EAGAIN;
            ret = -1;
            len = 0;
            break;
        }

        atomic_fetch_add(&handle->ctrl->tx_waiters, 1);
        if (handle->lock_type == UFIFO_LOCK_NONE) {
            len = __ufifo_unused_len(handle);
            if (len >= size) {
                atomic_fetch_sub(&handle->ctrl->tx_waiters, 1);
                break;
            }
        }

        if (wait_type == UFIFO_WAIT_BLOCK) {
            ret = __ufifo_efd_wait(handle->efd_wr, handle);
        } else {
            long rem = __ufifo_remaining_ms(&deadline);
            ret = __ufifo_efd_timedwait(handle->efd_wr, handle, rem);
        }
        atomic_fetch_sub(&handle->ctrl->tx_waiters, 1);

        if (ret) {
            errno = ret > 0 ? ret : -ret;
            len = 0;
            break;
        }
    }

    *out_len = len;
    return ret;
}

static inline int __ufifo_wait_for_data(ufifo_t *handle, ufifo_wait_type_e wait_type, long millisec, size_t *out_len)
{
    int ret = 0;
    size_t len;
    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);
    struct timespec deadline;

    if (wait_type == UFIFO_WAIT_TIMED) {
        __ufifo_calc_deadline(millisec, &deadline);
    }

    while (1) {
        len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out), READ_ONCE(handle->kfifo.in));
        if (len > 0)
            break;

        if (wait_type == UFIFO_WAIT_NONE) {
            errno = EAGAIN;
            ret = -1;
            len = 0;
            break;
        }

        atomic_fetch_add(&rx_ctrl->rx_waiters, 1);
        if (handle->lock_type == UFIFO_LOCK_NONE) {
            len = __ufifo_peek_len(handle, READ_ONCE(handle->kfifo.out), smp_load_acquire(handle->kfifo.in));
            if (len > 0) {
                atomic_fetch_sub(&rx_ctrl->rx_waiters, 1);
                break;
            }
        }

        if (wait_type == UFIFO_WAIT_BLOCK) {
            ret = __ufifo_efd_wait(handle->efd_rd, handle);
        } else {
            long rem = __ufifo_remaining_ms(&deadline);
            ret = __ufifo_efd_timedwait(handle->efd_rd, handle, rem);
        }
        atomic_fetch_sub(&rx_ctrl->rx_waiters, 1);

        if (ret) {
            errno = ret > 0 ? ret : -ret;
            len = 0;
            break;
        }
    }

    *out_len = len;
    return ret;
}

static inline __attribute__((always_inline)) size_t
__ufifo_put(ufifo_t *handle, void *buf, size_t size, ufifo_wait_type_e wait_type, long millisec)
{
    int ret;
    size_t len;

    if (unlikely(size > handle->kfifo.mask + 1)) {
        errno = EMSGSIZE;
        return 0;
    }

    __ufifo_data_lock(handle);
    ret = __ufifo_wait_for_space(handle, size, wait_type, millisec, &len);
    if (ret) {
        goto end;
    }

    if (unlikely(handle->hook.recput)) {
        size_t in = READ_ONCE(handle->kfifo.in);
        len = handle->kfifo.mask & in;
        len = handle->hook.recput(handle->shm_mem + len, handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (size != len) {
            errno = EIO;
            len = 0;
            goto end;
        }
        smp_store_release(handle->kfifo.in, in + len);
    } else {
        len = kfifo_in(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_notify_readers(handle);

end:
    __ufifo_data_unlock(handle);

    return len;
}

size_t ufifo_put(ufifo_t *handle, void *buf, size_t size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_put(handle, buf, size, UFIFO_WAIT_NONE, 0);
}

size_t ufifo_put_block(ufifo_t *handle, void *buf, size_t size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_put(handle, buf, size, UFIFO_WAIT_BLOCK, 0);
}

size_t ufifo_put_timeout(ufifo_t *handle, void *buf, size_t size, long millisec)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_put(handle, buf, size, UFIFO_WAIT_TIMED, millisec);
}

static inline __attribute__((always_inline)) size_t
__ufifo_get(ufifo_t *handle, void *buf, size_t size, ufifo_wait_type_e wait_type, long millisec)
{
    int ret;
    size_t len;
    __ufifo_data_lock(handle);
    ret = __ufifo_wait_for_data(handle, wait_type, millisec, &len);
    if (ret) {
        goto end;
    }

    if (unlikely(handle->hook.recsize && size < len)) {
        errno = ENOBUFS;
        len = 0;
        goto end;
    }

    size_t old_out = READ_ONCE(handle->kfifo.out);
    if (unlikely(handle->hook.recget)) {
        size_t out = old_out;
        len = handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (len == 0) {
            errno = EIO;
            goto end;
        }
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

    __ufifo_notify_writers(handle);

end:
    __ufifo_data_unlock(handle);

    return len;
}

size_t ufifo_get(ufifo_t *handle, void *buf, size_t size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_get(handle, buf, size, UFIFO_WAIT_NONE, 0);
}

size_t ufifo_get_block(ufifo_t *handle, void *buf, size_t size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_get(handle, buf, size, UFIFO_WAIT_BLOCK, 0);
}

size_t ufifo_get_timeout(ufifo_t *handle, void *buf, size_t size, long millisec)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_get(handle, buf, size, UFIFO_WAIT_TIMED, millisec);
}

static inline __attribute__((always_inline)) size_t
__ufifo_peek(ufifo_t *handle, void *buf, size_t size, ufifo_wait_type_e wait_type, long millisec)
{
    int ret = 0;
    size_t len;
    __ufifo_data_lock(handle);
    ret = __ufifo_wait_for_data(handle, wait_type, millisec, &len);
    if (ret) {
        goto end;
    }

    if (unlikely(handle->hook.recsize && size < len)) {
        errno = ENOBUFS;
        len = 0;
        goto end;
    }

    if (unlikely(handle->hook.recget)) {
        size_t out = READ_ONCE(handle->kfifo.out);
        len = handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (len == 0) {
            errno = EIO;
            goto end;
        }
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out_peek(&handle->kfifo, handle->shm_mem, buf, size);
    }
end:
    __ufifo_data_unlock(handle);
    return len;
}

size_t ufifo_peek(ufifo_t *handle, void *buf, size_t size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_peek(handle, buf, size, UFIFO_WAIT_NONE, 0);
}

size_t ufifo_peek_block(ufifo_t *handle, void *buf, size_t size)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_peek(handle, buf, size, UFIFO_WAIT_BLOCK, 0);
}

size_t ufifo_peek_timeout(ufifo_t *handle, void *buf, size_t size, long millisec)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return __ufifo_peek(handle, buf, size, UFIFO_WAIT_TIMED, millisec);
}

static int __ufifo_seek_tag(ufifo_t *handle, uint32_t tag, bool newest)
{
    int ret = -ESPIPE;
    size_t len, tmp;
    size_t target_pos = 0;
    bool found = false;

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
    size_t in_val = READ_ONCE(handle->kfifo.in);
    while (tmp != in_val) {
        len = __ufifo_peek_len(handle, tmp, in_val);
        if (len == 0)
            break;
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            found = true;
            target_pos = tmp;
            if (!newest)
                break;
        }
        tmp += len;
    }

    if (found) {
        tmp = target_pos;
        ret = 0;
    } else {
        ret = -ESPIPE;
    }

    size_t old_out = READ_ONCE(handle->kfifo.out);
    smp_store_release(handle->kfifo.out, tmp);
    if (__ufifo_is_shared(handle)) {
        if (old_out == smp_load_acquire(&handle->ctrl->cached_min_out)) {
            __ufifo_update_cached_min_out(handle);
        }
    }
    __ufifo_notify_writers(handle);

    __ufifo_data_unlock(handle);
    return ret;
}

int ufifo_oldest(ufifo_t *handle, uint32_t tag)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_seek_tag(handle, tag, false);
}

int ufifo_newest(ufifo_t *handle, uint32_t tag)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_seek_tag(handle, tag, true);
}
