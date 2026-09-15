#ifndef _KFIFO_H_
#define _KFIFO_H_

#include <string.h>
#include "utils.h"

typedef struct __kfifo {
    size_t *in;
    size_t *out;
    size_t mask;
} kfifo_t;

static inline __attribute__((always_inline)) int kfifo_init(kfifo_t *fifo, size_t size)
{
    *fifo->in = 0;
    *fifo->out = 0;

    if (size < 2) {
        fifo->mask = 0;
        return -1;
    }
    fifo->mask = size - 1;

    return 0;
}

static inline __attribute__((always_inline)) size_t __kfifo_unused(kfifo_t *fifo)
{
    size_t in = READ_ONCE(fifo->in);
    size_t out = smp_load_acquire(fifo->out);
    return (fifo->mask + 1) - (in - out);
}

static inline __attribute__((always_inline)) void __kfifo_copy_in(kfifo_t *fifo, char *base, const char *src, size_t len, size_t off)
{
    size_t size = fifo->mask + 1;
    size_t l;

    off &= fifo->mask;
    l = min(len, size - off);

    memcpy(base + off, src, l);
    memcpy(base, src + l, len - l);
}

static inline __attribute__((always_inline)) size_t kfifo_in(kfifo_t *fifo, void *base, const void *buf, size_t len)
{
    size_t l;

    l = __kfifo_unused(fifo);
    if (len > l)
        len = l;

    size_t in = READ_ONCE(fifo->in);
    __kfifo_copy_in(fifo, base, buf, len, in);
    smp_store_release(fifo->in, in + len);
    return len;
}

static inline __attribute__((always_inline)) void __kfifo_copy_out(kfifo_t *fifo, char *base, char *dst, size_t len, size_t off)
{
    size_t size = fifo->mask + 1;
    size_t l;

    off &= fifo->mask;
    l = min(len, size - off);

    memcpy(dst, base + off, l);
    memcpy(dst + l, base, len - l);
}

static inline __attribute__((always_inline)) size_t kfifo_out_peek(kfifo_t *fifo, void *base, void *buf, size_t len)
{
    size_t l;
    size_t in = smp_load_acquire(fifo->in);
    size_t out = READ_ONCE(fifo->out);

    l = in - out;
    if (len > l)
        len = l;

    __kfifo_copy_out(fifo, base, buf, len, out);
    return len;
}

static inline __attribute__((always_inline)) size_t kfifo_out(kfifo_t *fifo, void *base, void *buf, size_t len)
{
    len = kfifo_out_peek(fifo, base, buf, len);
    size_t out = READ_ONCE(fifo->out);
    smp_store_release(fifo->out, out + len);
    return len;
}

#endif /* _KFIFO_H_ */