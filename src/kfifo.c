#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "kfifo.h"
#include "log2.h"
#include "utils.h"

#define smp_wmb __sync_synchronize

/*
 * internal helper to calculate the unused elements in a fifo
 */
static inline unsigned int __kfifo_unused(struct __kfifo *fifo)
{
    return (fifo->mask + 1) - (fifo->in - fifo->out);
}

int kfifo_init(struct __kfifo *fifo, void *buffer, unsigned int size)
{
    size = rounddown_pow_of_two(size);

    fifo->in = 0;
    fifo->out = 0;
    fifo->data = buffer;

    if (size < 2) {
        fifo->mask = 0;
        return -EINVAL;
    }
    fifo->mask = size - 1;

    return 0;
}

static void __kfifo_copy_in(struct __kfifo *fifo, const void *src, unsigned int len, unsigned int off)
{
    unsigned int size = fifo->mask + 1;
    unsigned int l;

    off &= fifo->mask;
    l = min(len, size - off);

    memcpy(fifo->data + off, src, l);
    memcpy(fifo->data, src + l, len - l);
    /*
     * make sure that the data in the fifo is up to date before
     * incrementing the fifo->in index counter
     */
    smp_wmb();
}

unsigned int kfifo_in(struct __kfifo *fifo, const void *buf, unsigned int len)
{
    unsigned int l;

    l = __kfifo_unused(fifo);
    if (len > l)
        len = l;

    __kfifo_copy_in(fifo, buf, len, fifo->in);
    fifo->in += len;
    return len;
}

static void __kfifo_copy_out(struct __kfifo *fifo, void *dst, unsigned int len, unsigned int off)
{
    unsigned int size = fifo->mask + 1;
    unsigned int l;

    off &= fifo->mask;
    l = min(len, size - off);

    memcpy(dst, fifo->data + off, l);
    memcpy(dst + l, fifo->data, len - l);
    /*
     * make sure that the data is copied before
     * incrementing the fifo->out index counter
     */
    smp_wmb();
}

unsigned int kfifo_out_peek(struct __kfifo *fifo, void *buf, unsigned int len)
{
    unsigned int l;

    l = fifo->in - fifo->out;
    if (len > l)
        len = l;

    __kfifo_copy_out(fifo, buf, len, fifo->out);
    return len;
}

unsigned int kfifo_out(struct __kfifo *fifo, void *buf, unsigned int len)
{
    len = kfifo_out_peek(fifo, buf, len);
    fifo->out += len;
    return len;
}