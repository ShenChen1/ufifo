#ifndef UFIFO_PREDICATE_H
#define UFIFO_PREDICATE_H

#include "ufifo_internal.h"

static inline size_t __ufifo_tx_available_from_out(ufifo_t *handle, size_t out)
{
    const size_t length = ufifo_atomic_load_relaxed(handle->kfifo.in) - out;
    return handle->kfifo.mask + 1 - length;
}

static inline size_t __ufifo_tx_available_fast(ufifo_t *handle)
{
    const size_t out = __ufifo_is_shared(handle) ? ufifo_atomic_load_acquire(&handle->ctrl->cached_min_out)
                                                 : ufifo_atomic_load_acquire(handle->kfifo.out);
    return __ufifo_tx_available_from_out(handle, out);
}

/* SC loads here are paired with the publisher's SC fence after predicate publication. */
static inline size_t __ufifo_tx_available_after_arm(ufifo_t *handle)
{
    const size_t out = __ufifo_is_shared(handle) ? ufifo_atomic_load_seq_cst(&handle->ctrl->cached_min_out)
                                                 : ufifo_atomic_load_seq_cst(handle->kfifo.out);
    return __ufifo_tx_available_from_out(handle, out);
}

/* Byte streams use a 0/1 readiness marker; record mode preserves the next record's length. */
static inline size_t __ufifo_rx_data_len_at(ufifo_t *handle, size_t offset, size_t in)
{
    size_t length = (in == offset) ? 0 : 1;
    if (length && handle->hook.recsize) {
        uint8_t *data = (uint8_t *)handle->shm_mem;
        offset &= handle->kfifo.mask;
        length = handle->hook.recsize(data + offset, handle->kfifo.mask - offset + 1, data);
    }
    return length;
}

static inline size_t __ufifo_rx_data_len_fast(ufifo_t *handle)
{
    const size_t out = ufifo_atomic_load_relaxed(handle->kfifo.out);
    const size_t in = ufifo_atomic_load_acquire(handle->kfifo.in);
    return __ufifo_rx_data_len_at(handle, out, in);
}

static inline size_t __ufifo_rx_data_len_for_wait(ufifo_t *handle)
{
    const size_t out = ufifo_atomic_load_relaxed(handle->kfifo.out);
    const size_t in = ufifo_atomic_load_seq_cst(handle->kfifo.in);
    return __ufifo_rx_data_len_at(handle, out, in);
}

/* Keep this SC even if the ordinary fast predicate uses acquire. */
static inline size_t __ufifo_rx_data_len_after_arm(ufifo_t *handle)
{
    const size_t out = ufifo_atomic_load_relaxed(handle->kfifo.out);
    const size_t in = ufifo_atomic_load_seq_cst(handle->kfifo.in);
    return __ufifo_rx_data_len_at(handle, out, in);
}

#endif /* UFIFO_PREDICATE_H */
