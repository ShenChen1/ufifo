#ifndef UFIFO_INTERNAL_H
#define UFIFO_INTERNAL_H

#include <time.h>

#include "kfifo.h"
#include "ufifo.h"
#include "ufifo_layout.h"

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_NAME_BUF_SIZE (UFIFO_NAME_MAX + 1)
#define UFIFO_LIFETIME_LOCK_OFFSET 0
#define UFIFO_USER_LOCK_OFFSET(user_id) (1 + (user_id))

typedef enum {
    UFIFO_WAIT_NONE = 0,
    UFIFO_WAIT_BLOCK = 1,
    UFIFO_WAIT_TIMED = 2,
} ufifo_wait_type_e;

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
    size_t mapping_size;
    size_t shm_size;
    void *shm_mem;

    ufifo_ctrl_t *ctrl;
};

/* ufifo_sync.c */
int __ufifo_ctrl_lock(ufifo_t *handle);
int __ufifo_ctrl_unlock(ufifo_t *handle);
int __ufifo_data_lock(ufifo_t *handle);
int __ufifo_data_unlock(ufifo_t *handle);
int __ufifo_ofd_lock(int fd, size_t user_id);
int __ufifo_ofd_unlock(int fd, size_t user_id);
int __ufifo_is_user_dead(int fd, size_t user_id);
int __ufifo_lifetime_lock_exclusive(int fd, bool wait);
int __ufifo_lifetime_lock_shared(int fd, bool wait);
int __ufifo_lock_init(ufifo_t *handle, ufifo_lock_e type);
int __ufifo_lock_deinit(ufifo_t *handle);
void __ufifo_recover_state(ufifo_t *handle);

/* ufifo_lifetime.c */
int __ufifo_open_attached_fd(const char *name);
int __ufifo_force_unlink(const char *name);
int __ufifo_name_matches_fd(const char *name, int fd);

/* ufifo_wait.c */
uint32_t __ufifo_wait_arm(uint32_t *wait_word);
int __ufifo_futex_wait(uint32_t *wait_word, uint32_t expected, const struct timespec *deadline);
void __ufifo_wait_notify(uint32_t *wait_word);

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
size_t __ufifo_peek_data_len(ufifo_t *handle, size_t offset, size_t in_val);
int __ufifo_wait_for_space(ufifo_t *handle, size_t size, ufifo_wait_type_e wait_type, long millisec, size_t *out_len);
int __ufifo_wait_for_data(ufifo_t *handle, ufifo_wait_type_e wait_type, long millisec, size_t *out_len);

/*
 * Notify blocked writers that write-space may be available.
 * Must be called after any operation that may increase available buffer capacity:
 *   - reader consumes data (get / skip / oldest / newest)
 *   - reader unregisters (close)
 *   - dead reader reaped
 *   - FIFO reset
 *   - new reader joins with out=in (attach)
 * No-op when the TX wait word is not armed.
 */
static inline void __ufifo_notify_writers(ufifo_t *handle)
{
    __ufifo_wait_notify(&handle->ctrl->tx_wait_word);
}

static inline void __ufifo_notify_readers(ufifo_t *handle)
{
    if (__ufifo_is_shared(handle)) {
        for (size_t i = 0; i < handle->ctrl->max_users; i++) {
            if (!smp_load_acquire(&handle->ctrl->users[i].active))
                continue;
            __ufifo_wait_notify(&handle->ctrl->users[i].rx_wait_word);
        }
    } else {
        size_t rx_slot = __ufifo_rx_slot_id(handle);
        __ufifo_wait_notify(&handle->ctrl->users[rx_slot].rx_wait_word);
    }
}

#endif /* UFIFO_INTERNAL_H */
