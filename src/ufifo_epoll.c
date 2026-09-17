#include "ufifo_internal.h"
#include <errno.h>
#include <liburing.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

#define UFIFO_RING_DEPTH (64)
#define UFIFO_USERDATA_FUTEX (1ULL)
#define UFIFO_USERDATA_NOP (2ULL)

static int __ufifo_ring_init(struct io_uring **ring_out, int *fd_out)
{
    struct io_uring *ring = calloc(1, sizeof(struct io_uring));
    if (!ring) {
        return -ENOMEM;
    }

    int ret = io_uring_queue_init(UFIFO_RING_DEPTH, ring, 0);
    if (ret < 0) {
        free(ring);
        return ret;
    }

    *ring_out = ring;
    *fd_out = ring->ring_fd;
    return 0;
}

static void __ufifo_ring_drain_cqes(struct io_uring *ring, bool *wait_completed)
{
    struct io_uring_cqe *cqe;
    unsigned head;
    unsigned count = 0;

    io_uring_for_each_cqe(ring, head, cqe)
    {
        if (wait_completed && io_uring_cqe_get_data64(cqe) == UFIFO_USERDATA_FUTEX) {
            *wait_completed = true;
        }
        count++;
    }
    if (count > 0) {
        io_uring_cq_advance(ring, count);
    }
}

static int __ufifo_submit_futex_wait(struct io_uring *ring, uint32_t *futex, uint64_t user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
        if (!sqe) {
            return -ENOSPC;
        }
    }

    uint32_t snapshot = smp_load_acquire(futex);
    io_uring_prep_futex_wait(sqe, futex, snapshot, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0);
    sqe->user_data = user_data;
    return io_uring_submit(ring);
}

static int __ufifo_submit_nop(struct io_uring *ring, uint64_t user_data)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
        if (!sqe) {
            return -ENOSPC;
        }
    }

    io_uring_prep_nop(sqe);
    sqe->user_data = user_data;
    return io_uring_submit(ring);
}

static inline size_t __ufifo_tx_progress_state(ufifo_t *handle)
{
    if (__ufifo_is_shared(handle)) {
        return smp_load_acquire(&handle->ctrl->cached_min_out);
    } else {
        return smp_load_acquire(handle->kfifo.out);
    }
}

static void __ufifo_ring_exit(struct io_uring *ring, bool wait_pending)
{
    if (wait_pending) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (sqe) {
            io_uring_prep_cancel64(sqe, UFIFO_USERDATA_FUTEX, 0);
            io_uring_submit(ring);
        }
    }
    io_uring_queue_exit(ring);
}

void __ufifo_ring_destroy(ufifo_t *handle)
{
    pthread_mutex_lock(&handle->ring_mutex);
    if (handle->rx_ring) {
        __ufifo_ring_exit(handle->rx_ring, handle->rx_wait_pending);
        free(handle->rx_ring);
        handle->rx_ring = NULL;
        handle->rx_ring_fd = -1;
        handle->rx_wait_pending = false;
    }
    if (handle->tx_ring) {
        __ufifo_ring_exit(handle->tx_ring, handle->tx_wait_pending);
        free(handle->tx_ring);
        handle->tx_ring = NULL;
        handle->tx_ring_fd = -1;
        handle->tx_wait_pending = false;
    }
    pthread_mutex_unlock(&handle->ring_mutex);
}

int ufifo_get_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    pthread_mutex_lock(&handle->ring_mutex);
    if (!handle->rx_ring) {
        int ret = __ufifo_ring_init(&handle->rx_ring, &handle->rx_ring_fd);
        if (ret < 0) {
            pthread_mutex_unlock(&handle->ring_mutex);
            return ret;
        }
    }

    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);
    bool wait_done = false;
    __ufifo_ring_drain_cqes(handle->rx_ring, &wait_done);
    if (wait_done) {
        handle->rx_wait_pending = false;
    }

    if (!handle->rx_wait_pending) {
        if (__ufifo_submit_futex_wait(handle->rx_ring, &rx_ctrl->futex_rx, UFIFO_USERDATA_FUTEX) >= 0) {
            handle->rx_wait_pending = true;
        }
    }

    atomic_xchg(&rx_ctrl->futex_rx_armed, 1);

    if (smp_load_acquire(handle->kfifo.in) != READ_ONCE(handle->kfifo.out)) {
        __ufifo_submit_nop(handle->rx_ring, UFIFO_USERDATA_NOP);
    }

    int fd = handle->rx_ring_fd;
    pthread_mutex_unlock(&handle->ring_mutex);
    return fd;
}

int ufifo_get_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    pthread_mutex_lock(&handle->ring_mutex);
    if (!handle->tx_ring) {
        int ret = __ufifo_ring_init(&handle->tx_ring, &handle->tx_ring_fd);
        if (ret < 0) {
            pthread_mutex_unlock(&handle->ring_mutex);
            return ret;
        }
    }

    bool wait_done = false;
    __ufifo_ring_drain_cqes(handle->tx_ring, &wait_done);
    if (wait_done) {
        handle->tx_wait_pending = false;
    }

    if (!handle->tx_wait_pending) {
        if (__ufifo_submit_futex_wait(handle->tx_ring, &handle->ctrl->futex_tx, UFIFO_USERDATA_FUTEX) >= 0) {
            handle->tx_wait_pending = true;
        }
    }

    atomic_xchg(&handle->ctrl->futex_tx_armed, 1);

    size_t unused = __ufifo_unused_len(handle);
    if (unused > 0) {
        __ufifo_submit_nop(handle->tx_ring, UFIFO_USERDATA_NOP);
    }

    int fd = handle->tx_ring_fd;
    pthread_mutex_unlock(&handle->ring_mutex);
    return fd;
}

int ufifo_drain_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    pthread_mutex_lock(&handle->ring_mutex);
    if (!handle->rx_ring) {
        pthread_mutex_unlock(&handle->ring_mutex);
        return -EINVAL;
    }

    ufifo_sub_ctrl_t *rx_ctrl = __ufifo_rx_ctrl(handle);
    bool wait_done = false;

    __ufifo_ring_drain_cqes(handle->rx_ring, &wait_done);
    if (wait_done) {
        handle->rx_wait_pending = false;
    }

    if (!handle->rx_wait_pending) {
        if (__ufifo_submit_futex_wait(handle->rx_ring, &rx_ctrl->futex_rx, UFIFO_USERDATA_FUTEX) >= 0) {
            handle->rx_wait_pending = true;
        }
    }

    size_t saved_in = smp_load_acquire(handle->kfifo.in);
    atomic_xchg(&rx_ctrl->futex_rx_armed, 1);

    if (smp_load_acquire(handle->kfifo.in) != saved_in) {
        __ufifo_submit_nop(handle->rx_ring, UFIFO_USERDATA_NOP);
    }

    pthread_mutex_unlock(&handle->ring_mutex);
    return 0;
}

int ufifo_drain_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);

    pthread_mutex_lock(&handle->ring_mutex);
    if (!handle->tx_ring) {
        pthread_mutex_unlock(&handle->ring_mutex);
        return -EINVAL;
    }

    bool wait_done = false;

    __ufifo_ring_drain_cqes(handle->tx_ring, &wait_done);
    if (wait_done) {
        handle->tx_wait_pending = false;
    }

    if (!handle->tx_wait_pending) {
        if (__ufifo_submit_futex_wait(handle->tx_ring, &handle->ctrl->futex_tx, UFIFO_USERDATA_FUTEX) >= 0) {
            handle->tx_wait_pending = true;
        }
    }

    size_t saved_out = __ufifo_tx_progress_state(handle);
    atomic_xchg(&handle->ctrl->futex_tx_armed, 1);

    if (__ufifo_tx_progress_state(handle) != saved_out) {
        __ufifo_submit_nop(handle->tx_ring, UFIFO_USERDATA_NOP);
    }

    pthread_mutex_unlock(&handle->ring_mutex);
    return 0;
}
