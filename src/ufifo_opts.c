#include "ufifo_internal.h"
#include "ufifo_predicate.h"
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

static inline __attribute__((always_inline)) int __ufifo_begin_data_operation(ufifo_t *handle,
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

static size_t __ufifo_peek_tag(ufifo_t *handle, size_t offset)
{
    size_t ret = 0;

    if (handle->hook.rectag) {
        offset &= handle->kfifo.mask;
        ret = handle->hook.rectag(handle->shm_mem + offset, handle->kfifo.mask - offset + 1, handle->shm_mem);
    }

    return ret;
}

static inline int __ufifo_finish_data_operation(ufifo_t *handle, const ufifo_wait_result_t *result, int ret)
{
    if (!result->data_lock_held)
        return ret;
    const int unlock_ret = __ufifo_data_unlock(handle);
    if (ret >= 0 && unlock_ret < 0) {
        errno = -unlock_ret;
        return unlock_ret;
    }
    return ret;
}

static inline int __ufifo_prepare_write_space(ufifo_t *handle,
                                              size_t size,
                                              ufifo_wait_type_e wait_type,
                                              const struct timespec *deadline,
                                              ufifo_wait_result_t *result)
{
    if (wait_type == UFIFO_WAIT_NONE) {
        result->length = __ufifo_tx_available_fast(handle);
        if (result->length >= size)
            return 0;
        if (!__ufifo_is_shared(handle)) {
            result->length = 0;
            errno = EAGAIN;
            return -EAGAIN;
        }
    }
    return __ufifo_wait_for_space(handle, size, wait_type, deadline, result);
}

static inline int __ufifo_publish_data(ufifo_t *handle, void *buf, size_t size, size_t *length)
{
    if (unlikely(handle->hook.recput)) {
        const size_t in = ufifo_atomic_load_relaxed(handle->kfifo.in);
        const size_t offset = handle->kfifo.mask & in;
        *length = handle->hook.recput(handle->shm_mem + offset, handle->kfifo.mask - offset + 1, handle->shm_mem, buf);
        if (size != *length) {
            errno = EIO;
            *length = 0;
            return -EIO;
        }
        ufifo_atomic_store_release(handle->kfifo.in, in + *length);
    } else {
        *length = kfifo_in(&handle->kfifo, handle->shm_mem, buf, size);
    }
    __ufifo_notify_readers(handle);
    return 0;
}

static inline int __ufifo_prepare_read_size(ufifo_t *handle, size_t *size, size_t record_length)
{
    if (unlikely(handle->hook.recsize && *size < record_length)) {
        errno = ENOBUFS;
        return -ENOBUFS;
    }
    if (handle->hook.recsize)
        *size = record_length;
    return 0;
}

static inline __attribute__((always_inline)) ssize_t
__ufifo_put(ufifo_t *handle, void *buf, size_t size, ufifo_wait_type_e wait_type, long millisec)
{
    int perm_ret = __ufifo_check_write_permission(handle);
    if (perm_ret < 0)
        return perm_ret;

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
    ret = __ufifo_prepare_write_space(handle, size, wait_type, deadline, &wait_result);
    if (ret < 0)
        goto end;
    ret = __ufifo_publish_data(handle, buf, size, &len);

end:
    ret = __ufifo_finish_data_operation(handle, &wait_result, ret);
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
    int perm_ret = __ufifo_check_read_permission(handle);
    if (perm_ret < 0)
        return perm_ret;

    int ret;
    size_t len = 0;
    struct timespec deadline_storage;
    const struct timespec *deadline;
    ufifo_wait_result_t wait_result = { .data_lock_held = true };
    ret = __ufifo_begin_data_operation(handle, wait_type, millisec, &deadline_storage, &deadline);
    if (ret < 0)
        return ret;
    if (wait_type == UFIFO_WAIT_NONE) {
        len = __ufifo_rx_data_len_fast(handle);
        if (len == 0) {
            errno = EAGAIN;
            ret = -EAGAIN;
            goto end;
        }
    } else {
        ret = __ufifo_wait_for_data(handle, wait_type, deadline, &wait_result);
        len = wait_result.length;
        if (ret < 0)
            goto end;
    }

    ret = __ufifo_prepare_read_size(handle, &size, len);
    if (ret < 0) {
        len = 0;
        goto end;
    }

    size_t old_out = ufifo_atomic_load_relaxed(handle->kfifo.out);
    if (unlikely(handle->hook.recget)) {
        size_t out = old_out;
        len = handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (len == 0) {
            errno = EIO;
            ret = -EIO;
            goto end;
        }
        ufifo_atomic_store_release(handle->kfifo.out, out + len);
    } else {
        len = kfifo_out(&handle->kfifo, handle->shm_mem, buf, size);
    }

    __ufifo_notify_after_consume(handle, old_out);

end:
    ret = __ufifo_finish_data_operation(handle, &wait_result, ret);
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
    int perm_ret = __ufifo_check_read_permission(handle);
    if (perm_ret < 0)
        return perm_ret;

    int ret = 0;
    size_t len = 0;
    struct timespec deadline_storage;
    const struct timespec *deadline;
    ufifo_wait_result_t wait_result = { .data_lock_held = true };
    ret = __ufifo_begin_data_operation(handle, wait_type, millisec, &deadline_storage, &deadline);
    if (ret < 0)
        return ret;
    if (wait_type == UFIFO_WAIT_NONE) {
        len = __ufifo_rx_data_len_fast(handle);
        if (len == 0) {
            errno = EAGAIN;
            ret = -EAGAIN;
            goto end;
        }
    } else {
        ret = __ufifo_wait_for_data(handle, wait_type, deadline, &wait_result);
        len = wait_result.length;
        if (ret < 0)
            goto end;
    }

    ret = __ufifo_prepare_read_size(handle, &size, len);
    if (ret < 0) {
        len = 0;
        goto end;
    }

    if (unlikely(handle->hook.recget)) {
        size_t out = ufifo_atomic_load_relaxed(handle->kfifo.out);
        len = handle->kfifo.mask & out;
        len = handle->hook.recget(handle->shm_mem + len, handle->kfifo.mask - len + 1, handle->shm_mem, buf);
        if (len == 0) {
            errno = EIO;
            ret = -EIO;
            goto end;
        }
    } else {
        len = kfifo_out_peek(&handle->kfifo, handle->shm_mem, buf, size);
    }
end:
    ret = __ufifo_finish_data_operation(handle, &wait_result, ret);
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
    int perm_ret = __ufifo_check_read_permission(handle);
    if (perm_ret < 0)
        return perm_ret;

    int ret = -ESPIPE;
    size_t len, tmp;
    size_t target_pos = 0;
    bool found = false;

    int lock_ret = __ufifo_data_lock(handle);
    if (lock_ret < 0) {
        errno = -lock_ret;
        return lock_ret;
    }
    tmp = ufifo_atomic_load_relaxed(handle->kfifo.out);
    size_t in_val = ufifo_atomic_load_acquire(handle->kfifo.in);
    while (tmp != in_val) {
        len = __ufifo_rx_data_len_at(handle, tmp, in_val);
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

    size_t old_out = ufifo_atomic_load_relaxed(handle->kfifo.out);
    ufifo_atomic_store_release(handle->kfifo.out, tmp);
    __ufifo_notify_after_consume(handle, old_out);

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
