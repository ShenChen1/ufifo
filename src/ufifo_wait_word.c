#include "ufifo_wait_word.h"

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

uint32_t __ufifo_wait_arm(ufifo_atomic_uint32_t *wait_word)
{
    return ufifo_atomic_fetch_or_seq_cst(wait_word, UFIFO_WAIT_ARMED) | UFIFO_WAIT_ARMED;
}

int __ufifo_futex_wait(ufifo_atomic_uint32_t *wait_word, uint32_t expected, const struct timespec *deadline)
{
    int ret = syscall(SYS_futex, wait_word, FUTEX_WAIT_BITSET, expected, deadline, NULL, FUTEX_BITSET_MATCH_ANY);

    if (ret == 0 || errno == EAGAIN)
        return 0;
    return -errno;
}

void __ufifo_wait_notify(ufifo_atomic_uint32_t *wait_word)
{
    /* Together with SC arm and predicate recheck, this StoreLoad edge prevents lost wakeups. */
    ufifo_atomic_thread_fence_seq_cst();
    uint32_t observed = ufifo_atomic_load_seq_cst(wait_word);

    while (observed & UFIFO_WAIT_ARMED) {
        const uint32_t next_epoch = observed + 1U;
        if (!ufifo_atomic_compare_exchange_acq_rel(wait_word, &observed, next_epoch))
            continue;
        syscall(SYS_futex, wait_word, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        return;
    }
}
