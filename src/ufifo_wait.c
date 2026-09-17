#include "ufifo_internal.h"

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "utils.h"

#define UFIFO_WAIT_ARMED 1U

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
