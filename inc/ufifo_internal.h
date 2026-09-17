#ifndef UFIFO_INTERNAL_H
#define UFIFO_INTERNAL_H

#include "kfifo.h"
#include "ufifo.h"
#include "ufifo_layout.h"

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_NAME_BUF_SIZE (UFIFO_NAME_MAX)

/*
 * Byte range definition for Open File Description (OFD) locks:
 * Offset 0: Exclusively reserved for queue initialization lock (__ufifo_init_lock).
 * Offset 1..1+max_users: Exclusively reserved for user slot liveness detection (__ufifo_ofd_lock).
 */
#define UFIFO_OFD_INIT_OFFSET (0ULL)
#define UFIFO_OFD_USER_OFFSET_BASE (1ULL)

#define UFIFO_CHECK_HANDLE(handle, ...)                    \
    do {                                                   \
        if (!(handle) || (handle)->magic != UFIFO_MAGIC) { \
            errno = EINVAL;                                \
            return __VA_ARGS__;                            \
        }                                                  \
    } while (0)

struct ufifo {
    uint32_t magic;

    char name[UFIFO_NAME_BUF_SIZE];
    size_t user_id;
    bool is_shared;
    ufifo_lock_e lock_type;

    ufifo_hook_t hook;
    kfifo_t kfifo;

    int shm_fd;
    size_t shm_size;
    void *shm_base;
    void *data_mem;
    ufifo_ctrl_t *ctrl;

    /* io_uring epoll bridge (lazily initialized) */
    pthread_mutex_t ring_mutex; /* protects rx_ring and tx_ring operations */
    struct io_uring *rx_ring;   /* NULL until rx epoll is requested */
    int rx_ring_fd;             /* io_uring fd for rx epoll, -1 if unused */
    bool rx_wait_pending;       /* true if a FUTEX_WAIT is queued in the ring */
    struct io_uring *tx_ring;   /* NULL until tx epoll is requested */
    int tx_ring_fd;             /* io_uring fd for tx epoll, -1 if unused */
    bool tx_wait_pending;       /* true if a FUTEX_WAIT is queued in the ring */
};

/* ufifo_sync.c */
int __ufifo_ctrl_lock(ufifo_t *handle);
int __ufifo_ctrl_unlock(ufifo_t *handle);
int __ufifo_data_lock(ufifo_t *handle);
int __ufifo_data_unlock(ufifo_t *handle);
int __ufifo_ofd_lock(int fd, size_t user_id);
int __ufifo_ofd_unlock(int fd, size_t user_id);
int __ufifo_is_user_dead(int fd, size_t user_id);
int __ufifo_init_lock(int fd);
int __ufifo_init_wait(int fd);
int __ufifo_init_unlock(int fd);
int __ufifo_lock_init(ufifo_t *handle, ufifo_lock_e type);
int __ufifo_lock_deinit(ufifo_t *handle);
void __ufifo_recover_state(ufifo_t *handle);

/* futex-based wait/notify (ufifo_sync.c) */
int __ufifo_futex_wait(uint32_t *futex, uint32_t expected, ufifo_t *handle);
int __ufifo_futex_timedwait(uint32_t *futex, uint32_t expected, ufifo_t *handle, long millisec);
void __ufifo_futex_notify(uint32_t *futex, int32_t *waiters, int32_t *armed);

/* io_uring epoll bridge (ufifo_epoll.c) */
void __ufifo_ring_destroy(ufifo_t *handle);

/* ufifo_init.c */
void __ufifo_reap_dead_user(ufifo_t *handle, size_t user_id);
static inline bool __ufifo_is_shared(ufifo_t *handle)
{
    return handle->is_shared;
}
static inline size_t __ufifo_rx_slot_id(ufifo_t *handle)
{
    return __ufifo_is_shared(handle) ? handle->user_id : handle->ctrl->max_users;
}
static inline size_t __ufifo_rx_slot_count(ufifo_t *handle)
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
size_t __ufifo_unused_len(ufifo_t *handle);
size_t __ufifo_peek_len(ufifo_t *handle, size_t offset, size_t in_val);

/*
 * Notify blocked writers that write-space may be available.
 * Must be called after any operation that may increase available buffer capacity.
 * No-op when no writers are waiting and epoll is not armed.
 */
static inline void __ufifo_notify_writers(ufifo_t *handle)
{
    __ufifo_futex_notify(&handle->ctrl->futex_tx, &handle->ctrl->tx_waiters, &handle->ctrl->futex_tx_armed);
}

static inline void __ufifo_notify_readers(ufifo_t *handle)
{
    if (__ufifo_is_shared(handle)) {
        for (size_t i = 0; i < handle->ctrl->max_users; i++) {
            if (!smp_load_acquire(&handle->ctrl->users[i].active))
                continue;
            __ufifo_futex_notify(&handle->ctrl->users[i].futex_rx,
                                 &handle->ctrl->users[i].rx_waiters,
                                 &handle->ctrl->users[i].futex_rx_armed);
        }
    } else {
        size_t rx_slot = __ufifo_rx_slot_id(handle);
        __ufifo_futex_notify(&handle->ctrl->users[rx_slot].futex_rx,
                             &handle->ctrl->users[rx_slot].rx_waiters,
                             &handle->ctrl->users[rx_slot].futex_rx_armed);
    }
}

#endif /* UFIFO_INTERNAL_H */
