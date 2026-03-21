/**
 * SPMC (Single Producer, Multiple Consumer) stress test under SHARED + LOCK_NONE.
 *
 * In SHARED data mode each consumer receives a broadcast copy of every record.
 * LOCK_NONE is safe here because there is exactly one writer updating `in` and
 * each consumer independently updates its own `out` pointer.
 *
 * Validation per consumer:
 *   - record indices arrive in strictly increasing order (0 → NUM)
 *   - record payload matches the expected content
 */

#include "ufifo.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NUM 1000000
#define FIFO_SIZE 4096
#define CONSUMER_COUNT 4

typedef struct {
    unsigned int size;
    unsigned int index;
    char buf[0];
} record_t;

static const char PAYLOAD[] = "hello";
static const unsigned int PAYLOAD_SIZE = sizeof(PAYLOAD);
static const unsigned int RECORD_SIZE = sizeof(record_t) + sizeof(PAYLOAD);

/* Shared control: producer handle (owner) */
static ufifo_t *producer_fifo = NULL;

static unsigned int recsize(unsigned char *p1, unsigned int n1, unsigned char *p2)
{
    unsigned int size = sizeof(record_t);

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

    assert(size == PAYLOAD_SIZE);
    return sizeof(record_t) + size;
}

/* ---- Producer thread ---- */
/*
 * In SHARED mode the ALLOC handle is also registered as a user with its own
 * `out` pointer.  If we never call ufifo_get on it, __ufifo_min_out treats
 * the producer as the slowest consumer and the FIFO appears permanently full.
 * After each successful put we therefore drain the record we just wrote so that
 * our `out` keeps pace with `in`.
 */

static void *producer_thread(void *arg)
{
    (void)arg;
    unsigned int ret;
    char buf[64];
    record_t *rec = (record_t *)buf;

    rec->index = 0;
    while (1) {
        rec->size = PAYLOAD_SIZE;
        memcpy(rec->buf, PAYLOAD, rec->size);
        ret = ufifo_put(producer_fifo, rec, RECORD_SIZE);
        if (ret) {
            assert(ret == RECORD_SIZE);
            /* Advance producer's own out pointer */
            ufifo_newest(producer_fifo, rec->index);
            if (rec->index == NUM) {
                break;
            }
            rec->index++;
        } else {
            sched_yield();
        }
    }

    return NULL;
}

/* ---- Consumer thread ---- */

typedef struct {
    int id;
    ufifo_t *handle;
} consumer_arg_t;

static atomic_int consumers_passed = 0;
static atomic_int consumers_failed = 0;

static void *consumer_thread(void *arg)
{
    consumer_arg_t *ctx = (consumer_arg_t *)arg;
    unsigned int ret;
    char buf[64];
    record_t *rec = (record_t *)buf;
    unsigned int expected_index = 0;

    while (1) {
        memset(buf, 0, sizeof(buf));
        ret = ufifo_get(ctx->handle, rec, sizeof(buf));
        if (ret == 0) {
            sched_yield();
            continue;
        }
        if (expected_index != rec->index) {
            printf("consumer[%d]: FAIL index mismatch, expected %u got %u\n", ctx->id, expected_index, rec->index);
            atomic_fetch_add(&consumers_failed, 1);
            return NULL;
        }
        if (memcmp(rec->buf, PAYLOAD, PAYLOAD_SIZE) != 0) {
            printf("consumer[%d]: FAIL payload mismatch at index %u\n", ctx->id, rec->index);
            atomic_fetch_add(&consumers_failed, 1);
            return NULL;
        }
        if (rec->index == NUM) {
            break;
        }
        expected_index++;
    }

    printf("consumer[%d]: PASS (%u records verified)\n", ctx->id, NUM + 1);
    atomic_fetch_add(&consumers_passed, 1);
    return NULL;
}

/* ---- Main ---- */

int main(void)
{
    printf("=== SPMC SHARED + LOCK_NONE stress test ===\n");
    printf("ufifo version: %s\n", ufifo_get_version());
    printf("producer: 1, consumers: %d, records: %d\n\n", CONSUMER_COUNT, NUM + 1);

    int ret;

    /* Create producer FIFO (ALLOC, SHARED, LOCK_NONE) */
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = CONSUMER_COUNT + 1;
    init.hook.recsize = recsize;

    ret = ufifo_open("nolock_spmc", &init, &producer_fifo);
    assert(ret == 0);
    (void)ret;

    /* Attach consumer handles (each gets its own independent out pointer) */
    consumer_arg_t consumer_args[CONSUMER_COUNT];
    pthread_t consumer_threads[CONSUMER_COUNT];

    for (int i = 0; i < CONSUMER_COUNT; i++) {
        ufifo_init_t attach = {};
        attach.opt = UFIFO_OPT_ATTACH;
        attach.hook.recsize = recsize;

        consumer_args[i].id = i;
        consumer_args[i].handle = NULL;
        ret = ufifo_open("nolock_spmc", &attach, &consumer_args[i].handle);
        assert(ret == 0);
        (void)ret;
    }

    /* Start consumer threads first so they are ready */
    for (int i = 0; i < CONSUMER_COUNT; i++) {
        pthread_create(&consumer_threads[i], NULL, consumer_thread, &consumer_args[i]);
    }

    /* Short delay to let consumers register and start polling */
    usleep(10000);

    /* Start producer thread */
    pthread_t prod_thread;
    pthread_create(&prod_thread, NULL, producer_thread, NULL);

    /* Wait for completion */
    pthread_join(prod_thread, NULL);
    for (int i = 0; i < CONSUMER_COUNT; i++) {
        pthread_join(consumer_threads[i], NULL);
    }

    /* Cleanup */
    for (int i = 0; i < CONSUMER_COUNT; i++) {
        ufifo_close(consumer_args[i].handle);
    }
    ufifo_destroy(producer_fifo);

    /* Final report */
    int passed = atomic_load(&consumers_passed);
    int failed = atomic_load(&consumers_failed);
    printf("\nresult: %d/%d consumers passed, %d failed\n", passed, CONSUMER_COUNT, failed);
    printf("test %s\n", (passed == CONSUMER_COUNT) ? "PASSED" : "FAILED");
    return (passed == CONSUMER_COUNT) ? 0 : 1;
}