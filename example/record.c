#include "ufifo.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* fifo size in elements (bytes) */
#define FIFO_SIZE 128

static const char *expected_result[] = {
    "a", "bb", "ccc", "dddd", "eeeee", "ffffff", "ggggggg", "hhhhhhhh", "iiiiiiiii", "jjjjjjjjjj",
};

ufifo_t *test = NULL;

typedef struct {
    unsigned int size;
    char buf[0];
} record_t;

static size_t recsize(uint8_t *p1, size_t n1, uint8_t *p2)
{
    size_t size = sizeof(record_t);

    if (n1 >= size) {
        record_t *rec = (record_t *)p1;
        size = rec->size;
    } else {
        record_t rec;
        char *p = (char *)(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        size = rec.size;
    }

    return sizeof(record_t) + size;
}

int main(void)
{
    char buf[100];
    record_t *rec = (void *)buf;
    size_t i;
    ssize_t ret;
    char hello[] = { "hello" };

    printf("record fifo test start\n");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.max_users = 1;
    init.hook.recsize = recsize;
    ufifo_open("record", &init, &test);

    rec->size = sizeof(hello);
    memcpy(rec->buf, hello, rec->size);
    ufifo_put(test, rec, sizeof(record_t) + rec->size);

    /* show the size of the next record in the fifo */
    printf("fifo peek len: %zu\n", ufifo_peek_len(test));

    /* put in variable length data */
    for (i = 0; i < 10; i++) {
        rec->size = i + 1;
        memset(rec->buf, 'a' + i, rec->size);
        ufifo_put(test, rec, sizeof(record_t) + rec->size);
    }

    /* skip first element of the fifo */
    printf("skip 1st element\n");
    ufifo_skip(test);

    printf("fifo len: %zu\n", ufifo_len(test));

    /* show the first record without removing from the fifo */
    ret = ufifo_peek(test, rec, sizeof(buf));
    if (ret < 0) {
        fprintf(stderr, "ufifo_peek failed: %s\n", strerror((int)-ret));
        return 1;
    }
    rec->buf[(size_t)ret - sizeof(record_t)] = '\0';
    if (ret > 0)
        printf("%.*s\n", (int)ret, rec->buf);

    /* check the correctness of all values in the fifo */
    i = 0;
    while (ufifo_len(test)) {
        ret = ufifo_get(test, rec, sizeof(buf));
        if (ret < 0) {
            fprintf(stderr, "ufifo_get failed: %s\n", strerror((int)-ret));
            return 1;
        }
        rec->buf[(size_t)ret - sizeof(record_t)] = '\0';
        printf("item = %.*s\n", (int)ret, rec->buf);
        if (strcmp(rec->buf, expected_result[i++])) {
            printf("value mismatch: test failed\n");
            return -EIO;
        }
    }
    if (i != ARRAY_SIZE(expected_result)) {
        printf("size mismatch: test failed\n");
        return -EIO;
    }
    printf("test passed\n");

    ufifo_destroy(test);
    return 0;
}
