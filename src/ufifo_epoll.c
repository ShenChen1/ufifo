#include "ufifo_internal.h"
#include <errno.h>

int ufifo_get_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return handle->efd_rd;
}

int ufifo_get_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return handle->efd_wr;
}

int ufifo_drain_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    if (handle->efd_rd < 0)
        return -EINVAL;
    return __ufifo_efd_drain(handle->efd_rd);
}

int ufifo_drain_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    if (handle->efd_wr < 0)
        return -EINVAL;
    return __ufifo_efd_drain(handle->efd_wr);
}
