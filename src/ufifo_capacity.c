#include "ufifo_internal.h"

static size_t __ufifo_min_out(ufifo_t *handle)
{
    size_t in_val = ufifo_atomic_load_acquire(handle->kfifo.in);
    ssize_t max_distance = 0;
    size_t min_out = in_val;

    for (size_t i = 0; i < handle->ctrl->max_users; i++) {
        if (ufifo_atomic_load_acquire(&handle->ctrl->users[i].active)) {
            size_t out = ufifo_atomic_load_acquire(&handle->ctrl->users[i].out);
            ssize_t distance = (ssize_t)(in_val - out);
            if (distance > max_distance) {
                max_distance = distance;
                min_out = out;
            }
        }
    }
    return min_out;
}

bool __ufifo_update_cached_min_out(ufifo_t *handle)
{
    size_t min_out = __ufifo_min_out(handle);
    size_t cached = ufifo_atomic_load_acquire(&handle->ctrl->cached_min_out);

    while ((ssize_t)(min_out - cached) > 0) {
        if (ufifo_atomic_compare_exchange_acq_rel(&handle->ctrl->cached_min_out, &cached, min_out))
            return true;
    }
    return false;
}
