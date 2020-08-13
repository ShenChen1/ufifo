#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include "ufifo.h"

#define NUM 100000
#define FIFO_SIZE 128
#define PRODUCTSUM 3
#define CONSUMESUM 2

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
        printf("---------put start\n");
        ret = ufifo_put_ex(test, rec, rec->size + sizeof(record_t));
        printf("---------put end: %u\n", ret);
        if (ret) {
            assert(ret == rec->size + sizeof(record_t));
            rec->index++;
        }
        usleep(CONSUMESUM*100);
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
        printf("+++++++++get start\n");
        ret = ufifo_get_ex(test, rec, sizeof(buf));
        printf("+++++++++get end: %u\n", ret);
        if (ret != 0) {
            assert(!strcmp("hello", rec->buf));
        }
        usleep(PRODUCTSUM*100);
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
    ufifo_open("pressure-block", &init, &test);

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