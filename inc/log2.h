#ifndef _LOG2_H_
#define _LOG2_H_

/*
 * round up to nearest power of two
 */
static inline __attribute__((const))
unsigned int roundup_pow_of_two(unsigned int n)
{
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n++;
    return n;
}

/*
 * round down to nearest power of two
 */
static inline __attribute__((const))
unsigned int rounddown_pow_of_two(unsigned int n)
{
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return (n + 1) >> 1;
}

#endif /* _LOG2_H_ */