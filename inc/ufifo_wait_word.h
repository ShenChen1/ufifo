#ifndef UFIFO_WAIT_WORD_H
#define UFIFO_WAIT_WORD_H

#include <time.h>

#include "utils.h"

#define UFIFO_WAIT_ARMED 1U

uint32_t __ufifo_wait_arm(ufifo_atomic_uint32_t *wait_word);
int __ufifo_futex_wait(ufifo_atomic_uint32_t *wait_word, uint32_t expected, const struct timespec *deadline);
/* Caller must publish the predicate before notifying its wait word. */
void __ufifo_wait_notify(ufifo_atomic_uint32_t *wait_word);

#endif /* UFIFO_WAIT_WORD_H */
