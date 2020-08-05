#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "kfifo.h"

/* fifo size in elements (bytes) */
#define FIFO_SIZE   32

struct __kfifo test;

static const unsigned char expected_result[FIFO_SIZE] = {
     3,  4,  5,  6,  7,  8,  9,  0,
     1, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42,
};

int main()
{
    unsigned char   buf[6];
    unsigned char   i, j;
    unsigned int    ret;

    printf("byte stream fifo test start\n");

    /* put string into the fifo */
    kfifo_in(&test, "hello", 5);

    /* put values into the fifo */
    for (i = 0; i != 10; i++)
        kfifo_put(&test, i);

    /* show the number of used elements */
    printf("fifo len: %u\n", kfifo_len(&test));

    /* get max of 5 bytes from the fifo */
    i = kfifo_out(&test, buf, 5);
    printf("buf: %.*s\n", i, buf);

    /* get max of 2 elements from the fifo */
    ret = kfifo_out(&test, buf, 2);
    printf("ret: %d\n", ret);
    /* and put it back to the end of the fifo */
    ret = kfifo_in(&test, buf, ret);
    printf("ret: %d\n", ret);

    /* skip first element of the fifo */
    printf("skip 1st element\n");
    kfifo_skip(&test);

    /* put values into the fifo until is full */
    for (i = 20; kfifo_put(&test, i); i++)
        ;

    printf("queue len: %u\n", kfifo_len(&test));

    /* show the first value without removing from the fifo */
    if (kfifo_peek(&test, &i))
        printf("%d\n", i);

    /* check the correctness of all values in the fifo */
    j = 0;
    while (kfifo_get(&test, &i)) {
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

    return 0;
}