#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include "mutex.h"

struct __mutex {
    pthread_mutex_t mutex;
};

int mutex_init(mutex_t **handle)
{
    int ret;
    mutex_t *obj;

    obj = malloc(sizeof(mutex_t));
    if (obj == NULL) {
        return -ENOMEM;
    }

    ret = pthread_mutex_init(&obj->mutex, NULL);
    if (ret) {
        ret = -errno;
        free(obj);
        return ret;
    }

    *handle = obj;
    return 0;
}

int mutex_deinit(mutex_t *handle)
{
    pthread_mutex_destroy(&handle->mutex);
    free(handle);
    return 0;
}

int mutex_acquire(mutex_t *handle)
{
    return pthread_mutex_lock(&handle->mutex);
}

int mutex_release(mutex_t *handle)
{
    return pthread_mutex_unlock(&handle->mutex);
}