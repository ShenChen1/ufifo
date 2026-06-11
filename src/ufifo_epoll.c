#include "ufifo_internal.h"
#include <errno.h>
#include <stdint.h>

#include "utils.h"

int ufifo_get_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);

    __ufifo_ctrl_lock(handle);

    /* Arm the notification. If data is already available, fire immediately. */
    if (smp_load_acquire(handle->kfifo.in) != READ_ONCE(handle->kfifo.out)) {
        __ufifo_efd_post(handle->efd_rd);
        /* Leave epoll_armed = 0: producer will re-arm on next drain cycle */
    } else {
        smp_store_release(&rx_ctrl->epoll_armed, 1);
    }

    __ufifo_ctrl_unlock(handle);
    return handle->efd_rd;
}

int ufifo_get_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    __ufifo_ctrl_lock(handle);

    unsigned int unused = __ufifo_unused_len(handle);
    if (unused > 0) {
        __ufifo_efd_post(handle->efd_wr);
    } else {
        smp_store_release(&handle->ctrl->epoll_tx_armed, 1);
    }

    __ufifo_ctrl_unlock(handle);
    return handle->efd_wr;
}

int ufifo_drain_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    if (handle->efd_rd < 0)
        return -EINVAL;
    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);
    int ret = __ufifo_efd_drain(handle->efd_rd);
    smp_store_release(&rx_ctrl->epoll_armed, 1); /* re-arm */
    return ret;
}

int ufifo_drain_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    if (handle->efd_wr < 0)
        return -EINVAL;
    int ret = __ufifo_efd_drain(handle->efd_wr);
    smp_store_release(&handle->ctrl->epoll_tx_armed, 1); /* re-arm */
    return ret;
}
