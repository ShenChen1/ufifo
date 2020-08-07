#ifndef _UFIFO_H_
#define _UFIFO_H_

#include <stdint.h>

typedef enum {
    UFIFO_OPT_ALLOC,
    UFIFO_OPT_ATTACH,
    UFIFO_OPT_NONE,
} ufifo_opt_e;

typedef struct ufifo ufifo_t;

int ufifo_open(char *name, ufifo_opt_e opt, unsigned int size, ufifo_t **handle);
int ufifo_close(ufifo_t *handle);
unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_len(ufifo_t *handle);
void ufifo_skip(ufifo_t *handle);

#endif /* _UFIFO_H_ */