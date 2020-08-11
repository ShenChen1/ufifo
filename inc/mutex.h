#ifndef _MUTEX_H_
#define _MUTEX_H_

typedef struct __mutex mutex_t;

int mutex_init(mutex_t **handle);
int mutex_deinit(mutex_t *handle);
int mutex_acquire(mutex_t *handle);
int mutex_release(mutex_t *handle);

#endif /* _FDLOCK_H_ */