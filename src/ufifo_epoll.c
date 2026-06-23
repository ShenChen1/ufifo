#include "ufifo_internal.h"
#include <errno.h>
#include <stdint.h>

#include "utils.h"

int ufifo_get_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);

    /* Arm: ACQ_REL xchg provides store-load ordering with subsequent data check */
    atomic_xchg(&rx_ctrl->epoll_armed, 1);

    /* If data is already available, fire immediately. */
    if (smp_load_acquire(handle->kfifo.in) != READ_ONCE(handle->kfifo.out)) {
        if (atomic_xchg(&rx_ctrl->epoll_armed, 0) == 1) {
            __ufifo_efd_post(handle->efd_rd);
        }
    }

    return handle->efd_rd;
}

int ufifo_get_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    /* Arm: ACQ_REL xchg provides store-load ordering with subsequent space check */
    atomic_xchg(&handle->ctrl->epoll_tx_armed, 1);

    unsigned int unused = __ufifo_unused_len(handle);
    if (unused > 0) {
        if (atomic_xchg(&handle->ctrl->epoll_tx_armed, 0) == 1) {
            __ufifo_efd_post(handle->efd_wr);
        }
    }

    return handle->efd_wr;
}

int ufifo_drain_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    if (handle->efd_rd < 0)
        return -EINVAL;
    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);

    unsigned int saved_in = smp_load_acquire(handle->kfifo.in);
    int ret = __ufifo_efd_drain(handle->efd_rd);

    /* Re-arm: ACQ_REL xchg provides store-load ordering with subsequent data check */
    atomic_xchg(&rx_ctrl->epoll_armed, 1);

    if (smp_load_acquire(handle->kfifo.in) != saved_in) {
        if (atomic_xchg(&rx_ctrl->epoll_armed, 0) == 1) {
            __ufifo_efd_post(handle->efd_rd);
        }
    }

    return ret;
}

static inline unsigned int __ufifo_tx_progress_state(ufifo_t *handle)
{
    if (__ufifo_is_shared(handle)) {
        return smp_load_acquire(&handle->ctrl->cached_min_out);
    } else {
        return smp_load_acquire(handle->kfifo.out);
    }
}

int ufifo_drain_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    if (handle->efd_wr < 0)
        return -EINVAL;

    unsigned int saved_out = __ufifo_tx_progress_state(handle);
    int ret = __ufifo_efd_drain(handle->efd_wr);

    /* Re-arm: ACQ_REL xchg provides store-load ordering with subsequent space check */
    atomic_xchg(&handle->ctrl->epoll_tx_armed, 1);

    if (__ufifo_tx_progress_state(handle) != saved_out) {
        if (atomic_xchg(&handle->ctrl->epoll_tx_armed, 0) == 1) {
            __ufifo_efd_post(handle->efd_wr);
        }
    }

    return ret;
}
