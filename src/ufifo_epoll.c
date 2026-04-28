#include "ufifo_internal.h"
#include <errno.h>

#include "utils.h"

int ufifo_get_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    unsigned int idx = __ufifo_is_shared(handle) ? handle->user_id : 0;

    __ufifo_ctrl_lock(handle);

    /* Arm the notification. If data is already available, fire immediately. */
    if (READ_ONCE(handle->kfifo.in) != READ_ONCE(handle->kfifo.out)) {
        __ufifo_efd_post(handle->efd_rd);
        /* Leave epoll_armed = 0: producer will re-arm on next drain cycle */
    } else {
        smp_store_release(&handle->ctrl->users[idx].epoll_armed, 1);
    }

    __ufifo_ctrl_unlock(handle);
    return handle->efd_rd;
}

int ufifo_get_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    __ufifo_ctrl_lock(handle);

    unsigned int len = READ_ONCE(handle->kfifo.in) - READ_ONCE(handle->kfifo.out);
    unsigned int unused = *handle->kfifo.mask + 1 - len;
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
    unsigned int idx = __ufifo_is_shared(handle) ? handle->user_id : 0;
    int ret = __ufifo_efd_drain(handle->efd_rd);
    smp_store_release(&handle->ctrl->users[idx].epoll_armed, 1); /* re-arm */
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
