#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "ufifo.h"
#include "utils.h"

/* fifo size in elements (bytes) */
#define FIFO_SIZE	256

static const char *expected_result[] = {
    "a",
    //"bb",
    //"ccc",
    "dddd",
    //"eeeee",
    //"ffffff",
    "ggggggg",
    //"hhhhhhhh",
    //"iiiiiiiii",
    "jjjjjjjjjj",
};

ufifo_t *test = NULL;

typedef struct {
    unsigned int size;
    unsigned int tag;
    char buf[0];
} record_t;

static unsigned int recsize(unsigned char *p1, unsigned int n1, unsigned char *p2)
{
    unsigned int size = sizeof(record_t);

    if (n1 >= size) {
        record_t *rec = (record_t*)p1;
        size = rec->size;
    } else {
        record_t rec;
        void *p = (void *)(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        size = rec.size;
    }

    return sizeof(record_t) + size;
}

static unsigned int rectag(unsigned char *p1, unsigned int n1, unsigned char *p2)
{
    unsigned int tag;
    unsigned int size = sizeof(record_t);

    if (n1 >= size) {
        record_t *rec = (record_t*)p1;
        tag = rec->tag;
    } else {
        record_t rec;
        void *p = (void *)(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        tag = rec.tag;
    }

    return tag;
}

int main(void)
{
    char            buf[100];
    record_t       *rec = (void *)buf;
    unsigned int    i;
    unsigned int    ret;
    char hello[] = { "hello" };

    printf("record fifo test start\n");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_NONE;
    init.alloc.size = FIFO_SIZE;
    init.hook.recsize = recsize;
    init.hook.rectag = rectag;
    ufifo_open("record-tag", &init, &test);

    rec->size = sizeof(hello);
    memcpy(rec->buf, hello, rec->size);
    assert(ufifo_put(test, rec, sizeof(record_t) + rec->size) == sizeof(record_t) + rec->size);

    /* show the size of the next record in the fifo */
    printf("fifo peek len: %u\n", ufifo_peek_len(test));

    /* put in variable length data */
    for (i = 0; i < 10; i++) {
        rec->tag = i % 3 ? : 0xdeadbeef;
        rec->size = i + 1;
        memset(rec->buf, 'a' + i, rec->size);
        assert(ufifo_put(test, rec, sizeof(record_t) + rec->size) == sizeof(record_t) + rec->size);
    }

    /* skip first element of the fifo */
    printf("skip 1st element\n");
    ufifo_skip(test);

    printf("fifo len: %u\n", ufifo_len(test));

    /* show the first record without removing from the fifo */
    ret = ufifo_peek(test, rec, sizeof(buf));
    rec->buf[ret - sizeof(record_t)] = '\0';
    if (ret)
        printf("%.*s\n", ret, rec->buf);

    /* check the correctness of all values in the fifo */
    i = 0;
    while (ufifo_len(test)) {
        ufifo_oldest(test, 0xdeadbeef);
        ret = ufifo_get(test, rec, sizeof(buf));
        rec->buf[ret - sizeof(record_t)] = '\0';
        printf("item = %.*s\n", ret, rec->buf);
        if (strcmp(rec->buf, expected_result[i++])) {
            printf("value mismatch: test failed\n");
            return -EIO;
        }
    }
    if (i != ARRAY_SIZE(expected_result)) {
        printf("size mismatch: test failed\n");
        return -EIO;
    }

    /* put in variable length data */
    for (i = 0; i < 10; i++) {
        rec->tag = i % 3 ? : 0xdeadbeef;
        rec->size = i + 1;
        memset(rec->buf, 'a' + i, rec->size);
        assert(ufifo_put(test, rec, sizeof(record_t) + rec->size) == sizeof(record_t) + rec->size);
    }

    /* check the correctness of all values in the fifo */
    i = 0;
    ufifo_newest(test, 0xdeadbeef);
    ufifo_oldest(test, 0xdeadbeef);
    ret = ufifo_get(test, rec, sizeof(buf));
    rec->buf[ret - sizeof(record_t)] = '\0';
    printf("item = %.*s\n", ret, rec->buf);
    if (strcmp(rec->buf, expected_result[ARRAY_SIZE(expected_result) - 1])) {
        printf("value mismatch: test failed\n");
        return -EIO;
    }

    printf("test passed\n");

    ufifo_close(test);
    return 0;
}