#include "ufifo_internal.h"
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>

#include "utils.h"

static int __ufifo_prepare_deadline(ufifo_wait_type_e wait_type,
                                    long millisec,
                                    struct timespec *storage,
                                    const struct timespec **deadline)
{
    *deadline = NULL;
    if (wait_type != UFIFO_WAIT_TIMED)
        return 0;
    if (millisec < 0)
        millisec = 0;
    if (clock_gettime(CLOCK_MONOTONIC, storage) < 0)
        return -errno;
    storage->tv_sec += millisec / 1000;
    storage->tv_nsec += (millisec % 1000) * 1000000L;
    if (storage->tv_nsec >= 1000000000L) {
        storage->tv_sec++;
        storage->tv_nsec -= 1000000000L;
    }
    *deadline = storage;
    return 0;
}

static int __ufifo_begin_data_operation(ufifo_t *handle,
                                        ufifo_wait_type_e wait_type,
                                        long millisec,
                                        struct timespec *storage,
                                        const struct timespec **deadline)
{
    int ret = __ufifo_prepare_deadline(wait_type, millisec, storage, deadline);
    if (ret == 0)
        ret = __ufifo_data_lock_until(handle, *deadline);
    if (ret < 0)
        errno = -ret;
    return ret;
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
    size_t len = 0;

    if (__ufifo_is_shared(handle)) {
        out = smp_load_acquire(&handle->ctrl->cached_min_out);
    } else {
        out = smp_load_acquire(handle->kfifo.out);
    }

    len = READ_ONCE(handle->kfifo.in) - out;
    return handle->kfifo.mask + 1 - len;
}

size_t __ufifo_peek_data_len(ufifo_t *handle, size_t offset, size_t in_val)
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

static inline __attribute__((always_inline)) ssize_t
__ufifo_put(ufifo_t *handle, void *buf, size_t size, ufifo_wait_type_e wait_type, long millisec)
{
    int ret;
    size_t len = 0;
    struct timespec deadline_storage;
    const struct timespec *deadline;
    ufifo_wait_result_t wait_result = { .data_lock_held = true };

    if (unlikely(size > handle->kfifo.mask + 1)) {
        errno = EMSGSIZE;
        return -EMSGSIZE;
    }

    ret = __ufifo_begin_data_operation(handle, wait_type, millisec, &deadline_storage, &deadline);
    if (ret < 0)
        return ret;
    ret = __ufifo_wait_for_space(handle, size, wait_type, deadline, &wait_result);
    len = wait_result.length;
    if (ret < 0) {
        goto end;
    }

    if (unlikely(handle->hook.recput)) {
        size_t in = READ_ONCE(handle->kfifo.in);
        len = handle->kfifo.mask & in;
        len = handle->hook.recput(handle->shm_mem + len, handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (size != len) {
            errno = EIO;
            ret = -EIO;
            len = 0;
            goto end;
        }
        smp_store_release(handle->kfifo.in, in + len);
    } else {
        len = kfifo_in(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_notify_readers(handle);

end:
    if (wait_result.data_lock_held) {
        int unlock_ret = __ufifo_data_unlock(handle);
        if (ret >= 0 && unlock_ret < 0) {
            errno = -unlock_ret;
            ret = unlock_ret;
        }
    }

    return ret < 0 ? ret : (ssize_t)len;
}

ssize_t ufifo_put(ufifo_t *handle, void *buf, size_t size)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_put(handle, buf, size, UFIFO_WAIT_NONE, 0);
}

ssize_t ufifo_put_block(ufifo_t *handle, void *buf, size_t size)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_put(handle, buf, size, UFIFO_WAIT_BLOCK, 0);
}

ssize_t ufifo_put_timeout(ufifo_t *handle, void *buf, size_t size, long millisec)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_put(handle, buf, size, UFIFO_WAIT_TIMED, millisec);
}

static inline __attribute__((always_inline)) ssize_t
__ufifo_get(ufifo_t *handle, void *buf, size_t size, ufifo_wait_type_e wait_type, long millisec)
{
    int ret;
    size_t len = 0;
    struct timespec deadline_storage;
    const struct timespec *deadline;
    ufifo_wait_result_t wait_result = { .data_lock_held = true };
    ret = __ufifo_begin_data_operation(handle, wait_type, millisec, &deadline_storage, &deadline);
    if (ret < 0)
        return ret;
    ret = __ufifo_wait_for_data(handle, wait_type, deadline, &wait_result);
    len = wait_result.length;
    if (ret < 0) {
        goto end;
    }

    if (unlikely(handle->hook.recsize && size < len)) {
        errno = ENOBUFS;
        ret = -ENOBUFS;
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
            ret = -EIO;
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
    if (wait_result.data_lock_held) {
        int unlock_ret = __ufifo_data_unlock(handle);
        if (ret >= 0 && unlock_ret < 0) {
            errno = -unlock_ret;
            ret = unlock_ret;
        }
    }

    return ret < 0 ? ret : (ssize_t)len;
}

ssize_t ufifo_get(ufifo_t *handle, void *buf, size_t size)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_get(handle, buf, size, UFIFO_WAIT_NONE, 0);
}

ssize_t ufifo_get_block(ufifo_t *handle, void *buf, size_t size)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_get(handle, buf, size, UFIFO_WAIT_BLOCK, 0);
}

ssize_t ufifo_get_timeout(ufifo_t *handle, void *buf, size_t size, long millisec)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_get(handle, buf, size, UFIFO_WAIT_TIMED, millisec);
}

static inline __attribute__((always_inline)) ssize_t
__ufifo_peek(ufifo_t *handle, void *buf, size_t size, ufifo_wait_type_e wait_type, long millisec)
{
    int ret = 0;
    size_t len = 0;
    struct timespec deadline_storage;
    const struct timespec *deadline;
    ufifo_wait_result_t wait_result = { .data_lock_held = true };
    ret = __ufifo_begin_data_operation(handle, wait_type, millisec, &deadline_storage, &deadline);
    if (ret < 0)
        return ret;
    ret = __ufifo_wait_for_data(handle, wait_type, deadline, &wait_result);
    len = wait_result.length;
    if (ret < 0) {
        goto end;
    }

    if (unlikely(handle->hook.recsize && size < len)) {
        errno = ENOBUFS;
        ret = -ENOBUFS;
        len = 0;
        goto end;
    }

    if (unlikely(handle->hook.recget)) {
        size_t out = READ_ONCE(handle->kfifo.out);
        len = handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (len == 0) {
            errno = EIO;
            ret = -EIO;
            goto end;
        }
    } else {
        size = handle->hook.recsize ? min(size, len) : size;
        len = kfifo_out_peek(&handle->kfifo, handle->shm_mem, buf, size);
    }
end:
    if (wait_result.data_lock_held) {
        int unlock_ret = __ufifo_data_unlock(handle);
        if (ret >= 0 && unlock_ret < 0) {
            errno = -unlock_ret;
            ret = unlock_ret;
        }
    }
    return ret < 0 ? ret : (ssize_t)len;
}

ssize_t ufifo_peek(ufifo_t *handle, void *buf, size_t size)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_peek(handle, buf, size, UFIFO_WAIT_NONE, 0);
}

ssize_t ufifo_peek_block(ufifo_t *handle, void *buf, size_t size)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_peek(handle, buf, size, UFIFO_WAIT_BLOCK, 0);
}

ssize_t ufifo_peek_timeout(ufifo_t *handle, void *buf, size_t size, long millisec)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_peek(handle, buf, size, UFIFO_WAIT_TIMED, millisec);
}

static int __ufifo_seek_tag(ufifo_t *handle, uint32_t tag, bool newest)
{
    int ret = -ESPIPE;
    size_t len, tmp;
    size_t target_pos = 0;
    bool found = false;

    int lock_ret = __ufifo_data_lock(handle);
    if (lock_ret < 0) {
        errno = -lock_ret;
        return lock_ret;
    }
    tmp = READ_ONCE(handle->kfifo.out);
    size_t in_val = READ_ONCE(handle->kfifo.in);
    while (tmp != in_val) {
        len = __ufifo_peek_data_len(handle, tmp, in_val);
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

    int unlock_ret = __ufifo_data_unlock(handle);
    if (unlock_ret < 0) {
        errno = -unlock_ret;
        return unlock_ret;
    }
    if (ret < 0)
        errno = -ret;
    return ret;
}

int ufifo_oldest(ufifo_t *handle, uint32_t tag)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_seek_tag(handle, tag, false);
}

int ufifo_newest(ufifo_t *handle, uint32_t tag)
{
    int ret = __ufifo_validate_handle(handle);
    if (ret < 0)
        return ret;
    return __ufifo_seek_tag(handle, tag, true);
}
