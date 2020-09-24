#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include "ufifo.h"

#define NUM 100000
#define FIFO_SIZE 128
#define PRODUCTSUM 5
#define CONSUMESUM 5

typedef struct {
    unsigned int size;
    unsigned int index;
    char buf[0];
} record_t;

static int run_mode = 0;

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

    assert(size == sizeof("hello"));
    return sizeof(record_t) + size;
}

ufifo_t *test_product = NULL;
ufifo_t *test_consume = NULL;

void *product(void *arg)
{
    unsigned int ret;
    char buf[32];
    record_t *rec = (void *)buf;

    rec->index = 0;
    while (1) {
        rec->size = sizeof("hello");
        memcpy(rec->buf, "hello", rec->size);
        printf("-----[%zu]: put start\n", (size_t)arg);
        if (run_mode) {
            ret = ufifo_put(test_product, rec, rec->size + sizeof(record_t));
        } else {
            ret = ufifo_put_block(test_product, rec, rec->size + sizeof(record_t));
        }
        printf("-----[%zu]: put end: %u\n", (size_t)arg, ret);
        if (ret) {
            assert(ret == rec->size + sizeof(record_t));
            if (rec->index == NUM) {
                break;
            }
            rec->index++;
        }
    }

    return NULL;
}

void *consume(void *arg)
{
    unsigned int ret;
    char buf[32];
    record_t *rec = (void *)buf;

    while (1) {
        memset(buf, 0, sizeof(buf));
        printf("-----[%zu]: get start\n", (size_t)arg);
        if (run_mode) {
            ret = ufifo_get(test_consume, rec, sizeof(buf));
        } else {
            ret = ufifo_get_block(test_consume, rec, sizeof(buf));
        }
        printf("-----[%zu]: get end: %u\n", (size_t)arg, ret);
        if (ret != 0) {
            assert(!strcmp("hello", rec->buf));
            if (rec->index == NUM) {
                break;
            }
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        run_mode = 1;
    }

    pthread_t p[PRODUCTSUM];
    pthread_t c[CONSUMESUM];
    size_t i;

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_MUTEX;
    init.alloc.size = FIFO_SIZE;
    init.hook.recsize = recsize;
    ufifo_open("pressure", &init, &test_product);
    init.opt = UFIFO_OPT_ATTACH;
    init.lock = UFIFO_LOCK_MUTEX;
    init.hook.recsize = recsize;
    ufifo_open("pressure", &init, &test_consume);

    for (i = 0; i < PRODUCTSUM; ++i) {
        pthread_create(&p[i], NULL, product, (void *)i);
    }

    for (i = 0; i < CONSUMESUM; ++i){
        pthread_create(&c[i], NULL, consume, (void *)i);
    }

    for (i = 0; i < PRODUCTSUM; ++i) {
        pthread_join(p[i], NULL);
    }

    for (i = 0; i < CONSUMESUM; ++i) {
        pthread_join(c[i], NULL);
    }

    ufifo_close(test_consume);
    ufifo_destroy(test_product);
    return 0;
}