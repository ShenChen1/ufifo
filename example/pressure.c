#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include "ufifo.h"

#define NUM 100000
#define FIFO_SIZE 128
#define PRODUCTSUM 10
#define CONSUMESUM 10

typedef struct {
    unsigned int size;
    unsigned int index;
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

    assert(size == sizeof("hello"));
    return sizeof(record_t) + size;
}

ufifo_t *test = NULL;

void *product(void *arg)
{
    unsigned int ret;
    char buf[32];
    record_t *rec = (void *)buf;

    rec->index = 0;
    while (1) {
        rec->size = sizeof("hello");
        memcpy(rec->buf, "hello", rec->size);
        ret = ufifo_put(test, rec, rec->size + sizeof(record_t));
        if (ret) {
            assert(ret == rec->size + sizeof(record_t));
            if (rec->index == NUM) {
                break;
            }
            rec->index++;
        }
        usleep(*(useconds_t *)arg);
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
        ret = ufifo_get(test, rec, sizeof(buf));
        if (ret != 0) {
            assert(!strcmp("hello", rec->buf));
            if (rec->index == NUM) {
                break;
            }
        }
        usleep(*(useconds_t *)arg);
    }

    return NULL;
}

int main()
{
    pthread_t p[PRODUCTSUM];
    pthread_t c[CONSUMESUM];
    int i;

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_MUTEX;
    init.alloc.size = FIFO_SIZE;
    init.hook.recsize = recsize;
    ufifo_open("pressure", &init, &test);

    for (i = 0; i < PRODUCTSUM; ++i) {
        pthread_create(&p[i], NULL, product, &i);
    }

    for(i = 0; i < CONSUMESUM; ++i){
        pthread_create(&c[i], NULL, consume, &i);
    }

    for(i = 0; i < PRODUCTSUM; ++i) {
        pthread_join(p[i], NULL);
    }

    for(i = 0; i < CONSUMESUM; ++i) {
        pthread_join(c[i], NULL);
    }

    ufifo_close(test);
    return 0;
}