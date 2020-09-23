#ifndef _KFIFO_H_
#define _KFIFO_H_

#include <stdbool.h>

typedef struct __kfifo {
    unsigned int in;
    unsigned int out;
    unsigned int mask;
} kfifo_t;

int kfifo_init(kfifo_t *fifo, unsigned int size);
unsigned int kfifo_in(kfifo_t *fifo, void *base, const void *buf, unsigned int len);
unsigned int kfifo_out_peek(kfifo_t *fifo, void *base, void *buf, unsigned int len);
unsigned int kfifo_out(kfifo_t *fifo, void *base, void *buf, unsigned int len);

#endif /* _KFIFO_H_ */