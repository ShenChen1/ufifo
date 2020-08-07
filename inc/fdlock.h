#ifndef _FDLOCK_H_
#define _FDLOCK_H_

typedef struct fdlock fdlock_t;

int fdlock_acquire(const char *lock_path, fdlock_t **out_lock_handle);
int fdlock_release(fdlock_t **lock_handle_ptr);

#endif /* _FDLOCK_H_ */