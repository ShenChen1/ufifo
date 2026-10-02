#ifndef UFIFO_INTERNAL_H
#define UFIFO_INTERNAL_H

#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "kfifo.h"
#include "ufifo.h"
#include "ufifo_layout.h"
#include "ufifo_wait_word.h"

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_NAME_BUF_SIZE (UFIFO_NAME_MAX + 1)
#define UFIFO_LIFETIME_LOCK_OFFSET 0
#define UFIFO_USER_LOCK_OFFSET(user_id) (1 + (user_id))

typedef enum {
    UFIFO_WAIT_NONE = 0,
    UFIFO_WAIT_BLOCK = 1,
    UFIFO_WAIT_TIMED = 2,
} ufifo_wait_type_e;

typedef struct {
    size_t length;
    bool data_lock_held;
} ufifo_wait_result_t;

struct ufifo {
    uint32_t magic;
    pid_t owner_pid;
    bool registered;

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

/* ufifo_process.c */
int __ufifo_process_identity_init(void);
pid_t __ufifo_process_pid(void);

static inline int __ufifo_validate_handle(const ufifo_t *handle)
{
    int error = 0;
    if (handle == NULL || handle->magic != UFIFO_MAGIC)
        error = EINVAL;
    else if (handle->owner_pid != __ufifo_process_pid())
        error = ECHILD;
    if (error != 0)
        errno = error;
    return -error;
}

/* ufifo_sync.c */
int __ufifo_ctrl_lock(ufifo_t *handle);
int __ufifo_ctrl_unlock(ufifo_t *handle);
int __ufifo_data_lock(ufifo_t *handle);
int __ufifo_data_lock_until(ufifo_t *handle, const struct timespec *deadline);
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
int __ufifo_open_fd(const char *name, ufifo_init_t *init, bool *is_alloc);
int __ufifo_open_attached_fd(const char *name);
int __ufifo_force_unlink(const char *name);
int __ufifo_name_matches_fd(const char *name, int fd);

/* ufifo_wait.c */
int __ufifo_wait_for_space(
    ufifo_t *handle,
    size_t size,
    ufifo_wait_type_e wait_type,
    const struct timespec *deadline,
    ufifo_wait_result_t *result);
int __ufifo_wait_for_data(
    ufifo_t *handle,
    ufifo_wait_type_e wait_type,
    const struct timespec *deadline,
    ufifo_wait_result_t *result);

/* ufifo_init.c */
/* Caller must hold ctrl_mutex. Revalidates liveness immediately before mutation. */
bool __ufifo_reap_dead_user(ufifo_t *handle, size_t user_id);
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
static inline ufifo_atomic_uint32_t *__ufifo_rx_wait_word(ufifo_t *handle)
{
    return &handle->ctrl->rx_wait.value;
}
static inline ufifo_atomic_uint32_t *__ufifo_tx_wait_word(ufifo_t *handle)
{
    return &handle->ctrl->tx_wait.value;
}
void __ufifo_log(const char *fmt, ...);

/* ufifo_capacity.c */
/* Returns true only when SHARED available capacity increases. */
bool __ufifo_update_cached_min_out(ufifo_t *handle);
/* ufifo_state.c */
/* Caller must hold data_mutex unless the FIFO uses UFIFO_LOCK_NONE. */
void __ufifo_reset_data_locked(ufifo_t *handle);

/*
 * Notify blocked writers that write-space may be available.
 * Must be called after any operation that may increase available buffer capacity:
 *   - reader consumes data (get / skip / oldest / newest)
 *   - reader unregisters (close)
 *   - dead reader reaped
 *   - FIFO reset
 * Advances and wakes only when the shared TX word is armed.
 */
static inline void __ufifo_notify_writers(ufifo_t *handle)
{
    __ufifo_wait_notify(__ufifo_tx_wait_word(handle));
}

static inline void __ufifo_notify_readers(ufifo_t *handle)
{
    __ufifo_wait_notify(__ufifo_rx_wait_word(handle));
}

/* Caller has release-published out; SHARED capacity changes only when its minimum advances. */
static inline void __ufifo_notify_after_consume(ufifo_t *handle, size_t old_out)
{
    if (!__ufifo_is_shared(handle)) {
        __ufifo_notify_writers(handle);
    } else if (old_out == ufifo_atomic_load_acquire(&handle->ctrl->cached_min_out)
               && __ufifo_update_cached_min_out(handle)) {
        __ufifo_notify_writers(handle);
    }
}

#endif /* UFIFO_INTERNAL_H */
