#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "kfifo.h"

/* fifo size in elements (bytes) */
#define FIFO_SIZE	128

static const char *expected_result[] = {
    "a",
    "bb",
    "ccc",
    "dddd",
    "eeeee",
    "ffffff",
    "ggggggg",
    "hhhhhhhh",
    "iiiiiiiii",
    "jjjjjjjjjj",
};

int main(void)
{
    char            buf[100];
    unsigned int    i;
    unsigned int    ret;
    struct { unsigned char buf[6]; } hello = { "hello" };

    printf("record fifo test start\n");

    kfifo_in(&test, &hello, sizeof(hello));

    /* show the size of the next record in the fifo */
    printf("fifo peek len: %u\n", kfifo_peek_len(&test));

    /* put in variable length data */
    for (i = 0; i < 10; i++) {
        memset(buf, 'a' + i, i + 1);
        kfifo_in(&test, buf, i + 1);
    }

    /* skip first element of the fifo */
    printf("skip 1st element\n");
    kfifo_skip(&test);

    printf("fifo len: %u\n", kfifo_len(&test));

    /* show the first record without removing from the fifo */
    ret = kfifo_out_peek(&test, buf, sizeof(buf));
    if (ret)
        printf("%.*s\n", ret, buf);

    /* check the correctness of all values in the fifo */
    i = 0;
    while (!kfifo_is_empty(&test)) {
        ret = kfifo_out(&test, buf, sizeof(buf));
        buf[ret] = '\0';
        printf("item = %.*s\n", ret, buf);
        if (strcmp(buf, expected_result[i++])) {
            printf("value mismatch: test failed\n");
            return -EIO;
        }
    }
    if (i != ARRAY_SIZE(expected_result)) {
        printf("size mismatch: test failed\n");
        return -EIO;
    }
    printf("test passed\n");

    return 0;
}