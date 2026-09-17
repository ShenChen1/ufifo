#include "ufifo_internal.h"

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "utils.h"

#define UFIFO_WAIT_ARMED 1U

static void __ufifo_calc_deadline(long millisec, struct timespec *deadline)
{
    if (millisec < 0)
        millisec = 0;
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += millisec / 1000;
    deadline->tv_nsec += (millisec % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

uint32_t __ufifo_wait_arm(uint32_t *wait_word)
{
    return atomic_fetch_or(wait_word, UFIFO_WAIT_ARMED) | UFIFO_WAIT_ARMED;
}

int __ufifo_futex_wait(uint32_t *wait_word, uint32_t expected, const struct timespec *deadline)
{
    int ret = syscall(SYS_futex, wait_word, FUTEX_WAIT_BITSET, expected, deadline, NULL, FUTEX_BITSET_MATCH_ANY);

    if (ret == 0 || errno == EAGAIN)
        return 0;
    return -errno;
}

void __ufifo_wait_notify(uint32_t *wait_word)
{
    uint32_t observed = smp_load_acquire(wait_word);

    while (observed & UFIFO_WAIT_ARMED) {
        const uint32_t next_epoch = observed + 1;
        if (!atomic_cmpxchg(wait_word, &observed, next_epoch))
            continue;
        syscall(SYS_futex, wait_word, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        return;
    }
}

static int __ufifo_wait_on_word(ufifo_t *handle,
                                uint32_t *wait_word,
                                uint32_t expected,
                                const struct timespec *deadline)
{
    __ufifo_data_unlock(handle);
    const int ret = __ufifo_futex_wait(wait_word, expected, deadline);
    __ufifo_data_lock(handle);
    return ret;
}

static int __ufifo_try_reap_dead_readers(ufifo_t *handle)
{
    int cleaned = 0;

    for (size_t i = 0; i < handle->ctrl->max_users; i++) {
        if (i == handle->user_id || !smp_load_acquire(&handle->ctrl->users[i].active))
            continue;
        if (!__ufifo_is_user_dead(handle->ctrl_fd, i))
            continue;

        __ufifo_ctrl_lock(handle);
        if (READ_ONCE(&handle->ctrl->users[i].active)) {
            __ufifo_reap_dead_user(handle, i);
            cleaned = 1;
        }
        __ufifo_ctrl_unlock(handle);
    }

    if (cleaned) {
        __ufifo_update_cached_min_out(handle);
        __ufifo_notify_writers(handle);
    }
    return cleaned;
}

static size_t __ufifo_recheck_space(ufifo_t *handle, size_t size)
{
    size_t len = __ufifo_unused_len(handle);

    if (len >= size || !__ufifo_is_shared(handle))
        return len;
    __ufifo_update_cached_min_out(handle);
    __ufifo_try_reap_dead_readers(handle);
    return __ufifo_unused_len(handle);
}

int __ufifo_wait_for_space(ufifo_t *handle,
                           size_t size,
                           ufifo_wait_type_e wait_type,
                           long millisec,
                           size_t *out_len)
{
    int ret = 0;
    size_t len = 0;
    struct timespec deadline;
    const struct timespec *timeout = NULL;

    if (wait_type == UFIFO_WAIT_TIMED) {
        __ufifo_calc_deadline(millisec, &deadline);
        timeout = &deadline;
    }

    while ((len = __ufifo_recheck_space(handle, size)) < size) {
        if (wait_type == UFIFO_WAIT_NONE) {
            ret = -EAGAIN;
            break;
        }

        const uint32_t expected = __ufifo_wait_arm(&handle->ctrl->tx_wait_word);
        if (__ufifo_unused_len(handle) >= size)
            continue;
        ret = __ufifo_wait_on_word(handle, &handle->ctrl->tx_wait_word, expected, timeout);
        if (ret)
            break;
    }

    if (ret) {
        errno = ret > 0 ? ret : -ret;
        len = 0;
    }
    *out_len = len;
    return ret;
}

int __ufifo_wait_for_data(ufifo_t *handle, ufifo_wait_type_e wait_type, long millisec, size_t *out_len)
{
    int ret = 0;
    size_t len = 0;
    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);
    struct timespec deadline;
    const struct timespec *timeout = NULL;

    if (wait_type == UFIFO_WAIT_TIMED) {
        __ufifo_calc_deadline(millisec, &deadline);
        timeout = &deadline;
    }

    while ((len = __ufifo_peek_data_len(
                handle, READ_ONCE(handle->kfifo.out), smp_load_acquire(handle->kfifo.in))) == 0) {
        if (wait_type == UFIFO_WAIT_NONE) {
            ret = -EAGAIN;
            break;
        }

        const uint32_t expected = __ufifo_wait_arm(&rx_ctrl->rx_wait_word);
        len = __ufifo_peek_data_len(handle, READ_ONCE(handle->kfifo.out), smp_load_acquire(handle->kfifo.in));
        if (len > 0)
            continue;
        ret = __ufifo_wait_on_word(handle, &rx_ctrl->rx_wait_word, expected, timeout);
        if (ret)
            break;
    }

    if (ret) {
        errno = ret > 0 ? ret : -ret;
        len = 0;
    }
    *out_len = len;
    return ret;
}
