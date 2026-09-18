#include "ufifo.h"
#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* fifo size in elements (bytes) */
#define FIFO_SIZE 256

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
    uint32_t size;
    uint32_t tag;
    char *buf;
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

static size_t rectag(uint8_t *p1, size_t n1, uint8_t *p2)
{
    uint32_t tag;
    size_t size = sizeof(record_t);

    if (n1 >= size) {
        record_t *rec = (record_t *)p1;
        tag = rec->tag;
    } else {
        record_t rec;
        char *p = (char *)(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        tag = rec.tag;
    }

    return tag;
}

static size_t recput(uint8_t *p1, size_t n1, uint8_t *p2, void *arg)
{
    record_t *rec = arg;
    size_t a = 0, l = 0, _n1 = n1;
    uint8_t *p = NULL, *_p1 = p1, *_p2 = p2;

    // copy header
    p = (uint8_t *)(rec);
    a = sizeof(record_t);
    l = min(a, _n1);
    memcpy(_p1, p, l);
    memcpy(_p2, p + l, a - l);
    _n1 -= l;
    _p1 += l;
    _p2 += a - l;

    // copy data
    p = (uint8_t *)(rec->buf);
    a = rec->size;
    l = min(a, _n1);
    memcpy(_p1, p, l);
    memcpy(_p2, p + l, a - l);
    _n1 -= l;
    _p1 += l;
    _p2 += a - l;

    return rec->size + sizeof(record_t);
}

static size_t recget(uint8_t *p1, size_t n1, uint8_t *p2, void *arg)
{
    record_t *rec = arg;
    size_t a = 0, l = 0, _n1 = n1;
    uint8_t *p = NULL, *_p1 = p1, *_p2 = p2;

    // copy header
    p = (uint8_t *)(rec);
    a = sizeof(record_t);
    l = min(a, _n1);
    memcpy(p, _p1, l);
    memcpy(p + _n1, _p2, a - l);
    _n1 -= l;
    _p1 += l;
    _p2 += a - l;

    // copy data
    p = (uint8_t *)(rec->buf);
    a = rec->size;
    l = min(a, _n1);
    memcpy(p, _p1, l);
    memcpy(p + l, _p2, a - l);
    _n1 -= l;
    _p1 += l;
    _p2 += a - l;

    return rec->size + sizeof(record_t);
}

int main(void)
{
    char recbuf[32];
    char buf[100];
    record_t *rec = (void *)recbuf;
    size_t i;
    ssize_t ret;
    char hello[] = { "hello" };

    printf("record fifo test start\n");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.max_users = 1;
    init.hook.recsize = recsize;
    init.hook.rectag = rectag;
    init.hook.recput = recput;
    init.hook.recget = recget;
    ufifo_open("record-tag", &init, &test);

    // config buf ptr
    rec->buf = buf;

    rec->tag = 0;
    rec->size = sizeof(hello);
    memcpy(rec->buf, hello, rec->size);
    ret = ufifo_put(test, rec, sizeof(record_t) + rec->size);
    assert(ret == sizeof(record_t) + rec->size);

    /* show the size of the next record in the fifo */
    printf("fifo peek len: %zu\n", ufifo_peek_len(test));

    /* put in variable length data */
    for (i = 0; i < 10; i++) {
        rec->tag = i % 3 ? (uint32_t)(i % 3) : 0xdeadbeef;
        rec->size = i + 1;
        rec->buf = buf;
        memset(rec->buf, 'a' + i, rec->size);
        ret = ufifo_put(test, rec, sizeof(record_t) + rec->size);
        assert(ret == sizeof(record_t) + rec->size);
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
        ufifo_oldest(test, 0xdeadbeef);
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

    /* put in variable length data */
    for (i = 0; i < 10; i++) {
        rec->tag = i % 3 ? (uint32_t)(i % 3) : 0xdeadbeef;
        rec->size = i + 1;
        memset(rec->buf, 'a' + i, rec->size);
        ret = ufifo_put(test, rec, sizeof(record_t) + rec->size);
        assert(ret == sizeof(record_t) + rec->size);
    }

    /* check the correctness of all values in the fifo */
    i = 0;
    ufifo_newest(test, 0xdeadbeef);
    ufifo_oldest(test, 0xdeadbeef);
    ret = ufifo_get(test, rec, sizeof(buf));
    if (ret < 0) {
        fprintf(stderr, "ufifo_get failed: %s\n", strerror((int)-ret));
        return 1;
    }
    rec->buf[(size_t)ret - sizeof(record_t)] = '\0';
    printf("item = %.*s\n", (int)ret, rec->buf);
    if (strcmp(rec->buf, expected_result[ARRAY_SIZE(expected_result) - 1])) {
        printf("value mismatch: test failed\n");
        return -EIO;
    }

    printf("test passed\n");

    ufifo_destroy(test);
    return 0;
}
