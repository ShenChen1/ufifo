#ifndef UFIFO_INTERNAL_H
#define UFIFO_INTERNAL_H

#include "kfifo.h"
#include "ufifo.h"
#include "ufifo_layout.h"

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_NAME_BUF_SIZE (UFIFO_NAME_MAX)
#define UFIFO_CTRL_NAME_SUFFIX "_ctrl"
#define UFIFO_CTRL_NAME_BUF_SIZE (UFIFO_NAME_MAX + sizeof(UFIFO_CTRL_NAME_SUFFIX))

#define UFIFO_CHECK_HANDLE(handle, ...)                    \
    do {                                                   \
        if (!(handle) || (handle)->magic != UFIFO_MAGIC) { \
            return __VA_ARGS__;                            \
        }                                                  \
    } while (0)

struct ufifo {
    unsigned int magic;

    char name[UFIFO_NAME_BUF_SIZE];
    unsigned int user_id;
    int is_shared;
    ufifo_lock_e lock_type;

    ufifo_hook_t hook;
    kfifo_t kfifo;

    int shm_fd;
    size_t shm_size;
    void *shm_mem;

    int ctrl_fd;
    size_t ctrl_size;
    ufifo_ctrl_t *ctrl;

    /* eventfd-based notification */
    int efd_wr;       /* eventfd: write-space available (shared, one per FIFO) */
    int efd_rd;       /* eventfd: read-data available (this user's) */
    int *efd_rd_all;  /* SHARED: user eventfds; SOLE: user eventfds + reserved global eventfd */
    size_t efd_count; /* size of efd_rd_all */

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
int __ufifo_efd_wait(int efd, ufifo_t *handle);
int __ufifo_efd_timedwait(int efd, ufifo_t *handle, long millisec);
int __ufifo_efd_post(int efd);
int __ufifo_efd_drain(int efd);
int __ufifo_efd_notify(int efd, int *waiters, int *epoll_armed);

/* ufifo_broker.c — eventfd lifecycle (fork-based broker daemon) */
int __ufifo_acquire_eventfds(ufifo_t *handle, int is_alloc);
int __ufifo_broker_start(ufifo_t *handle);
void __ufifo_broker_wake_to_exit(const char *name);
int __ufifo_efd_create_all(ufifo_t *handle, unsigned int count);
void __ufifo_efd_close_all(ufifo_t *handle);

/* ufifo_init.c */
void __ufifo_reap_dead_user(ufifo_t *handle, unsigned int user_id);
static inline int __ufifo_is_shared(ufifo_t *handle)
{
    return handle->is_shared;
}
static inline unsigned int __ufifo_rx_slot_id(ufifo_t *handle)
{
    return __ufifo_is_shared(handle) ? handle->user_id : handle->ctrl->max_users;
}
static inline unsigned int __ufifo_rx_slot_count(ufifo_t *handle)
{
    return handle->ctrl->max_users + (__ufifo_is_shared(handle) ? 0U : 1U);
}
static inline ufifo_sub_ctrl_t *__ufifo_rx_ctrl(ufifo_t *handle)
{
    return &handle->ctrl->users[__ufifo_rx_slot_id(handle)];
}
void __ufifo_log(const char *fmt, ...);

/* ufifo_opts.c */
void __ufifo_update_cached_min_out(ufifo_t *handle);
unsigned int __ufifo_unused_len(ufifo_t *handle);

/*
 * Notify blocked writers / epoll-TX listeners that write-space may be available.
 * Must be called after any operation that may increase available buffer capacity:
 *   - reader consumes data (get / skip / oldest / newest / peek)
 *   - reader unregisters (close)
 *   - dead reader reaped
 *   - FIFO reset
 *   - new reader joins with out=in (attach)
 * No-op when no writers are waiting (tx_waiters == 0 && epoll_tx_armed == 0).
 */
static inline void __ufifo_notify_writers(ufifo_t *handle)
{
    __ufifo_efd_notify(handle->efd_wr, &handle->ctrl->tx_waiters, &handle->ctrl->epoll_tx_armed);
}

static inline void __ufifo_notify_readers(ufifo_t *handle)
{
    if (__ufifo_is_shared(handle)) {
        for (unsigned int i = 0; i < handle->ctrl->max_users; i++) {
            if (smp_load_acquire(&handle->ctrl->users[i].active))
                __ufifo_efd_notify(handle->efd_rd_all[i],
                                   &handle->ctrl->users[i].rx_waiters,
                                   &handle->ctrl->users[i].epoll_armed);
        }
    } else {
        unsigned int rx_slot = __ufifo_rx_slot_id(handle);
        __ufifo_efd_notify(handle->efd_rd_all[rx_slot],
                           &handle->ctrl->users[rx_slot].rx_waiters,
                           &handle->ctrl->users[rx_slot].epoll_armed);
    }
}

#endif /* UFIFO_INTERNAL_H */
