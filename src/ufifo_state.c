#include "ufifo_internal.h"
#include "ufifo_predicate.h"

#include <errno.h>
#include <limits.h>

#include "utils.h"

static int __ufifo_length_result(size_t length, ssize_t *result)
{
    if (length > SSIZE_MAX) {
        errno = EOVERFLOW;
        return -EOVERFLOW;
    }
    *result = (ssize_t)length;
    return 0;
}

ssize_t ufifo_size(ufifo_t *handle)
{
    int ret = __ufifo_validate_handle(handle);
    return ret < 0 ? ret : (ssize_t)(handle->kfifo.mask + 1);
}

void __ufifo_reset_data_locked(ufifo_t *handle)
{
    ufifo_atomic_store_release(handle->kfifo.in, 0);
    ufifo_atomic_store_release(handle->kfifo.out, 0);
    if (__ufifo_is_shared(handle)) {
        for (size_t i = 0; i < handle->ctrl->max_users; i++) {
            if (ufifo_atomic_load_acquire(&handle->ctrl->users[i].active))
                ufifo_atomic_store_release(&handle->ctrl->users[i].out, 0);
        }
        ufifo_atomic_store_release(&handle->ctrl->cached_min_out, 0);
    }
}

int ufifo_reset(ufifo_t *handle)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;

    ret = __ufifo_data_lock(handle);
    if (ret < 0) {
        errno = -ret;
        return ret;
    }
    __ufifo_reset_data_locked(handle);
    __ufifo_notify_writers(handle);
    ret = __ufifo_data_unlock(handle);
    if (ret < 0)
        errno = -ret;
    return ret;
}

ssize_t ufifo_len(ufifo_t *handle)
{
    ssize_t result;
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;

    ret = __ufifo_data_lock(handle);
    if (ret < 0) {
        errno = -ret;
        return ret;
    }
    size_t len = ufifo_atomic_load_relaxed(handle->kfifo.in) - ufifo_atomic_load_relaxed(handle->kfifo.out);
    ret = __ufifo_length_result(len, &result);
    if (ret == 0)
        ret = __ufifo_data_unlock(handle);
    else
        __ufifo_data_unlock(handle);
    if (ret < 0) {
        errno = -ret;
        return ret;
    }
    return result;
}

ssize_t ufifo_skip(ufifo_t *handle)
{
    ssize_t result;
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;

    ret = __ufifo_data_lock(handle);
    if (ret < 0) {
        errno = -ret;
        return ret;
    }
    size_t out = ufifo_atomic_load_relaxed(handle->kfifo.out);
    size_t len = __ufifo_rx_data_len_at(handle, out, ufifo_atomic_load_acquire(handle->kfifo.in));
    ret = __ufifo_length_result(len, &result);
    if (ret < 0) {
        __ufifo_data_unlock(handle);
        return ret;
    }
    ufifo_atomic_store_release(handle->kfifo.out, out + len);
    __ufifo_notify_after_consume(handle, out);
    ret = __ufifo_data_unlock(handle);
    if (ret < 0) {
        errno = -ret;
        return ret;
    }
    return result;
}

ssize_t ufifo_peek_len(ufifo_t *handle)
{
    ssize_t result;
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;

    ret = __ufifo_data_lock(handle);
    if (ret < 0) {
        errno = -ret;
        return ret;
    }
    size_t len = __ufifo_rx_data_len_fast(handle);
    ret = __ufifo_length_result(len, &result);
    if (ret == 0)
        ret = __ufifo_data_unlock(handle);
    else
        __ufifo_data_unlock(handle);
    if (ret < 0) {
        errno = -ret;
        return ret;
    }
    return result;
}
