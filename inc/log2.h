#ifndef _LOG2_H_
#define _LOG2_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Round up to nearest power of two.
 *
 * Returns 0 if:
 *   - n == 0
 *   - result cannot be represented by size_t
 */
static inline __attribute__((const))
size_t roundup_pow_of_two(size_t n)
{
    if (n == 0)
        return 0;

    n--;

    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;

#if SIZE_MAX > UINT32_MAX
    n |= n >> 32;
#endif

    return n + 1;
}

/*
 * Round down to nearest power of two.
 *
 * Returns 0 if n == 0.
 */
static inline __attribute__((const))
size_t rounddown_pow_of_two(size_t n)
{
    if (n == 0)
        return 0;

    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;

#if SIZE_MAX > UINT32_MAX
    n |= n >> 32;
#endif

    return n - (n >> 1);
}

#endif /* _LOG2_H_ */