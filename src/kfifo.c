#include "kfifo.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * internal helper to calculate the unused elements in a fifo
 *
 * Called by producer: in is own (relaxed), out is from consumer (acquire).
 */
static inline unsigned int __kfifo_unused(kfifo_t *fifo)
{
    unsigned int in = READ_ONCE(fifo->in);
    unsigned int out = smp_load_acquire(fifo->out);
    return (*fifo->mask + 1) - (in - out);
}

/*
 * kfifo_init - initialize a fifo
 * @fifo: the fifo to initialize
 * @size: the size of the fifo buffer (must be a power of 2)
 *
 * Note: The caller is responsible for ensuring size is a power of 2.
 * Use rounddown_pow_of_two() from log2.h before calling this function.
 */
int kfifo_init(kfifo_t *fifo, unsigned int size)
{
    *fifo->in = 0;
    *fifo->out = 0;

    if (size < 2) {
        *fifo->mask = 0;
        return -EINVAL;
    }
    *fifo->mask = size - 1;

    return 0;
}

static void __kfifo_copy_in(kfifo_t *fifo, char *base, const char *src, unsigned int len, unsigned int off)
{
    unsigned int size = *fifo->mask + 1;
    unsigned int l;

    off &= *fifo->mask;
    l = min(len, size - off);

    memcpy(base + off, src, l);
    memcpy(base, src + l, len - l);
}

unsigned int kfifo_in(kfifo_t *fifo, void *base, const void *buf, unsigned int len)
{
    unsigned int l;

    l = __kfifo_unused(fifo);
    if (len > l)
        len = l;

    unsigned int in = READ_ONCE(fifo->in);
    __kfifo_copy_in(fifo, base, buf, len, in);
    smp_store_release(fifo->in, in + len);
    return len;
}

static void __kfifo_copy_out(kfifo_t *fifo, char *base, char *dst, unsigned int len, unsigned int off)
{
    unsigned int size = *fifo->mask + 1;
    unsigned int l;

    off &= *fifo->mask;
    l = min(len, size - off);

    memcpy(dst, base + off, l);
    memcpy(dst + l, base, len - l);
}

/*
 * Consumer reads: in from producer (acquire), out is own (relaxed).
 */
unsigned int kfifo_out_peek(kfifo_t *fifo, void *base, void *buf, unsigned int len)
{
    unsigned int l;
    unsigned int in = smp_load_acquire(fifo->in);
    unsigned int out = READ_ONCE(fifo->out);

    l = in - out;
    if (len > l)
        len = l;

    __kfifo_copy_out(fifo, base, buf, len, out);
    return len;
}

unsigned int kfifo_out(kfifo_t *fifo, void *base, void *buf, unsigned int len)
{
    len = kfifo_out_peek(fifo, base, buf, len);
    unsigned int out = READ_ONCE(fifo->out);
    smp_store_release(fifo->out, out + len);
    return len;
}