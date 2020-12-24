#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "ufifo.h"
#include "utils.h"

/* fifo size in elements (bytes) */
#define FIFO_SIZE   32

static const unsigned char expected_result[FIFO_SIZE] = {
     3,  4,  5,  6,  7,  8,  9,  0,
     1, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42,
};

ufifo_t *test = NULL;

int main()
{
    unsigned char   buf[6];
    unsigned char   i, j;
    unsigned int    ret;

    printf("byte stream fifo test start\n");

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_FDLOCK;
    init.alloc.size = FIFO_SIZE;
    ufifo_open("bytestream", &init, &test);

    /* put string into the fifo */
    ufifo_put(test, "hello", 5);

    /* put values into the fifo */
    for (i = 0; i != 10; i++)
        ufifo_put(test, &i, 1);

    /* show the number of used elements */
    printf("fifo len: %u\n", ufifo_len(test));

    /* get max of 5 bytes from the fifo */
    i = ufifo_get(test, buf, 5);
    printf("buf: %.*s\n", i, buf);

    /* get max of 2 elements from the fifo */
    ret = ufifo_get(test, buf, 2);
    printf("ret: %u\n", ret);
    /* and put it back to the end of the zfifo */
    ret = ufifo_put(test, buf, ret);
    printf("ret: %u\n", ret);

    /* skip first element of the fifo */
    printf("skip 1st element\n");
    ufifo_skip(test);

    /* put values into the fifo until is full */
    for (i = 20; ufifo_put(test, &i, 1); i++)
        ;

    printf("queue len: %u\n", ufifo_len(test));

    /* show the first value without removing from the fifo */
    if (ufifo_peek(test, &i, 1))
        printf("%d\n", i);

    /* check the correctness of all values in the fifo */
    j = 0;
    while (ufifo_get(test, &i, 1)) {
        printf("item = %d\n", i);
        if (i != expected_result[j++]) {
            printf("value mismatch: test failed\n");
            return -EIO;
        }
    }
    if (j != ARRAY_SIZE(expected_result)) {
        printf("size mismatch: test failed\n");
        return -EIO;
    }
    printf("test passed\n");

    ufifo_destroy(test);
    return 0;
}