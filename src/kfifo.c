#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "kfifo.h"
#include "log2.h"
#include "utils.h"

/*
 * internal helper to calculate the unused elements in a fifo
 */
static inline unsigned int __kfifo_unused(kfifo_t *fifo)
{
    return (*fifo->mask + 1) - (*fifo->in - *fifo->out);
}

int kfifo_init(kfifo_t *fifo, unsigned int size)
{
    size = rounddown_pow_of_two(size);

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
    /*
     * make sure that the data in the fifo is up to date before
     * incrementing the fifo->in index counter
     */
    smp_wmb();
}

unsigned int kfifo_in(kfifo_t *fifo, void *base, const void *buf, unsigned int len)
{
    unsigned int l;

    l = __kfifo_unused(fifo);
    if (len > l)
        len = l;

    __kfifo_copy_in(fifo, base, buf, len, *fifo->in);
    *fifo->in += len;
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
    /*
     * make sure that the data is copied before
     * incrementing the fifo->out index counter
     */
    smp_wmb();
}

unsigned int kfifo_out_peek(kfifo_t *fifo, void *base, void *buf, unsigned int len)
{
    unsigned int l;

    l = *fifo->in - *fifo->out;
    if (len > l)
        len = l;

    __kfifo_copy_out(fifo, base, buf, len, *fifo->out);
    return len;
}

unsigned int kfifo_out(kfifo_t *fifo, void *base, void *buf, unsigned int len)
{
    len = kfifo_out_peek(fifo, base, buf, len);
    *fifo->out += len;
    return len;
}