#ifndef UFIFO_INTERNAL_H
#define UFIFO_INTERNAL_H
#include <limits.h>

#include "kfifo.h"
#include "ufifo.h"
#include "ufifo_layout.h"

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_CHECK_HANDLE(handle, ...)                     \
    do {                                                    \
        if (!(handle) || (handle)->magic != UFIFO_MAGIC) {  \
            return __VA_ARGS__;                             \
        }                                                   \
    } while (0)

struct ufifo {
    unsigned int magic;

    char name[NAME_MAX];
    unsigned int user_id;

    ufifo_hook_t hook;
    kfifo_t kfifo;
    sem_t *bsem_wr;
    sem_t *bsem_rd;

    int shm_fd;
    unsigned int shm_size;
    void *shm_mem;

    int ctrl_fd;
    size_t ctrl_size;
    ufifo_ctrl_t *ctrl;

    int rx_efd;
    int tx_efd;
};

/* ufifo_sync.c */
int __ufifo_ctrl_lock(ufifo_t *handle);
int __ufifo_ctrl_unlock(ufifo_t *handle);
int __ufifo_data_lock(ufifo_t *handle);
int __ufifo_data_unlock(ufifo_t *handle);
int __ufifo_ofd_lock(int fd, unsigned int user_id);
int __ufifo_ofd_unlock(int fd, unsigned int user_id);
int __ufifo_is_user_dead(int fd, unsigned int user_id);
int __ufifo_init_lock(int fd);
int __ufifo_init_wait(int fd);
int __ufifo_init_unlock(int fd);
int __ufifo_lock_init(ufifo_t *handle, ufifo_lock_e type);
int __ufifo_lock_deinit(ufifo_t *handle);
int __ufifo_bsem_init(sem_t *bsem, unsigned int value);
int __ufifo_bsem_deinit(sem_t *bsem);
int __ufifo_bsem_wait(sem_t *bsem, ufifo_t *handle);
int __ufifo_bsem_timedwait(sem_t *bsem, ufifo_t *handle, long millisec);
int __ufifo_bsem_post(sem_t *bsem);

/* ufifo_epoll.c */
void __ufifo_efd_notify_rx(ufifo_t *handle);
void __ufifo_efd_notify_tx(ufifo_t *handle);

/* ufifo_init.c */
void __ufifo_reap_dead_user(ufifo_t *handle, unsigned int user_id);
int __ufifo_is_shared(ufifo_t *handle);

#endif /* UFIFO_INTERNAL_H */
