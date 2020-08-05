#ifndef _KFIFO_H_
#define _KFIFO_H_

#include <stdbool.h>

struct __kfifo {
    unsigned int in;
    unsigned int out;
    unsigned int mask;
    unsigned int esize;
    void *data;
};

extern int kfifo_init(struct __kfifo *fifo, void *buffer, unsigned int size, size_t esize);
extern unsigned int kfifo_in(struct __kfifo *fifo, const void *buf, unsigned int len);
extern unsigned int kfifo_out(struct __kfifo *fifo, void *buf, unsigned int len);
extern unsigned int kfifo_out_peek(struct __kfifo *fifo, void *buf, unsigned int len);
extern void kfifo_reset(struct __kfifo *fifo);
extern void kfifo_reset_out(struct __kfifo *fifo);
extern unsigned int kfifo_len(struct __kfifo *fifo);
extern bool kfifo_is_empty(struct __kfifo *fifo);
extern bool kfifo_is_full(struct __kfifo *fifo);

#endif /* _KFIFO_H_ */