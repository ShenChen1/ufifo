#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include "ufifo.h"

/* fifo size in elements (bytes) */
#define FIFO_SIZE   32

static const unsigned char expected_result[FIFO_SIZE] = {
     3,  4,  5,  6,  7,  8,  9,  0,
     1, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42,
};


int main()
{
    pthread_create();



    return 0;
}