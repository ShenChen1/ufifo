#include "ufifo_internal.h"
#include "ufifo_predicate.h"

static int __ufifo_wait_on_word(ufifo_t *handle,
                                ufifo_atomic_uint32_t *wait_word,
                                uint32_t expected,
                                const struct timespec *deadline,
                                ufifo_wait_result_t *result)
{
    int unlock_ret = __ufifo_data_unlock(handle);
    result->data_lock_held = false;
    if (unlock_ret < 0)
        return unlock_ret;
    const int ret = __ufifo_futex_wait(wait_word, expected, deadline);
    const int lock_ret = __ufifo_data_lock_until(handle, deadline);
    if (lock_ret < 0)
        return lock_ret;
    result->data_lock_held = true;
    return ret;
}

static int __ufifo_try_reap_dead_readers(ufifo_t *handle)
{
    int cleaned = 0;

    for (size_t i = 0; i < handle->ctrl->max_users; i++) {
        if (i == handle->user_id || !ufifo_atomic_load_acquire(&handle->ctrl->users[i].active))
            continue;
        if (!__ufifo_is_user_dead(handle->shm_fd, i))
            continue;

        int ret = __ufifo_ctrl_lock(handle);
        if (ret < 0)
            continue;
        if (__ufifo_reap_dead_user(handle, i)) {
            cleaned = 1;
        }
        if (__ufifo_ctrl_unlock(handle) < 0)
            return cleaned;
    }

    if (cleaned && __ufifo_update_cached_min_out(handle))
        __ufifo_notify_writers(handle);
    return cleaned;
}

static size_t __ufifo_refresh_write_space(ufifo_t *handle, size_t size)
{
    size_t len = __ufifo_tx_available_fast(handle);

    if (len >= size || !__ufifo_is_shared(handle))
        return len;
    if (__ufifo_update_cached_min_out(handle))
        __ufifo_notify_writers(handle);
    __ufifo_try_reap_dead_readers(handle);
    return __ufifo_tx_available_fast(handle);
}

int __ufifo_wait_for_space(
    ufifo_t *handle,
    size_t size,
    ufifo_wait_type_e wait_type,
    const struct timespec *deadline,
    ufifo_wait_result_t *result)
{
    int ret = 0;
    size_t len = 0;

    while ((len = __ufifo_refresh_write_space(handle, size)) < size) {
        if (wait_type == UFIFO_WAIT_NONE) {
            ret = -EAGAIN;
            break;
        }

        ufifo_atomic_uint32_t *wait_word = __ufifo_tx_wait_word(handle);
        const uint32_t expected = __ufifo_wait_arm(wait_word);
        if (__ufifo_tx_available_after_arm(handle) >= size)
            continue;
        ret = __ufifo_wait_on_word(handle, wait_word, expected, deadline, result);
        if (ret)
            break;
    }

    if (ret) {
        errno = ret > 0 ? ret : -ret;
        len = 0;
    }
    result->length = len;
    return ret;
}

int __ufifo_wait_for_data(
    ufifo_t *handle,
    ufifo_wait_type_e wait_type,
    const struct timespec *deadline,
    ufifo_wait_result_t *result)
{
    int ret = 0;
    size_t len = 0;
    ufifo_atomic_uint32_t *wait_word = __ufifo_rx_wait_word(handle);

    while ((len = __ufifo_rx_data_len_for_wait(handle)) == 0) {
        if (wait_type == UFIFO_WAIT_NONE) {
            ret = -EAGAIN;
            break;
        }

        const uint32_t expected = __ufifo_wait_arm(wait_word);
        len = __ufifo_rx_data_len_after_arm(handle);
        if (len > 0)
            continue;
        ret = __ufifo_wait_on_word(handle, wait_word, expected, deadline, result);
        if (ret)
            break;
    }

    if (ret) {
        errno = ret > 0 ? ret : -ret;
        len = 0;
    }
    result->length = len;
    return ret;
}
