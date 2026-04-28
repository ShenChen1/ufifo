#ifndef UFIFO_INTERNAL_H
#define UFIFO_INTERNAL_H

#include "kfifo.h"
#include "ufifo.h"
#include "ufifo_layout.h"

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_CHECK_HANDLE(handle, ...)                    \
    do {                                                   \
        if (!(handle) || (handle)->magic != UFIFO_MAGIC) { \
            return __VA_ARGS__;                            \
        }                                                  \
    } while (0)

struct ufifo {
    unsigned int magic;

    char name[128];
    unsigned int user_id;

    ufifo_hook_t hook;
    kfifo_t kfifo;

    int shm_fd;
    unsigned int shm_size;
    void *shm_mem;

    int ctrl_fd;
    size_t ctrl_size;
    ufifo_ctrl_t *ctrl;

    /* eventfd-based notification */
    int efd_wr;       /* eventfd: write-space available (shared, one per FIFO) */
    int efd_rd;       /* eventfd: read-data available (this user's) */
    int *efd_rd_all;  /* array[max_users]: all readers' eventfds (for writer notify) */
    size_t efd_count; /* max_users: size of efd_rd_all */

    /* fd broker lifecycle (forked daemon, started by first open) */
    int is_broker_owner; /* 1 if this process forked the broker daemon */
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

/* eventfd operations */
int __ufifo_efd_create(void);
int __ufifo_efd_wait(int efd, ufifo_t *handle, int *waiters);
int __ufifo_efd_timedwait(int efd, ufifo_t *handle, long millisec, int *waiters);
int __ufifo_efd_post(int efd);
int __ufifo_efd_drain(int efd);

/* ufifo_broker.c — eventfd lifecycle (fork-based broker daemon) */
int __ufifo_acquire_eventfds(ufifo_t *handle, int is_alloc);
int __ufifo_broker_start(ufifo_t *handle);
int __ufifo_efd_create_all(ufifo_t *handle, unsigned int max_users);
void __ufifo_efd_close_all(ufifo_t *handle);

/* ufifo_init.c */
void __ufifo_reap_dead_user(ufifo_t *handle, unsigned int user_id);
int __ufifo_is_shared(ufifo_t *handle);
void __ufifo_log(const char *fmt, ...);

#endif /* UFIFO_INTERNAL_H */
