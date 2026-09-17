#include "ufifo_internal.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

static void default_log_cb(void *arg, const char *fmt, va_list ap)
{
    (void)arg;
    vfprintf(stdout, fmt, ap);
}

static ufifo_log_cb g_log_cb = default_log_cb;
static void *g_log_arg = NULL;

void ufifo_set_log_handler(ufifo_log_cb cb, void *arg)
{
    if (cb) {
        g_log_cb = cb;
        g_log_arg = arg;
    } else {
        g_log_cb = default_log_cb;
        g_log_arg = NULL;
    }
}

void __ufifo_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (g_log_cb) {
        g_log_cb(g_log_arg, fmt, ap);
    }
    va_end(ap);
}

void ufifo_dump(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle);
    __ufifo_ctrl_lock(handle);

    size_t mask = handle->kfifo.mask;
    size_t size = mask + 1;
    size_t in = READ_ONCE(handle->kfifo.in);
    size_t out = READ_ONCE(handle->kfifo.out);

    __ufifo_log("=== ufifo_dump: %s ===\n", handle->name);
    __ufifo_log("Shm fd: %d, Size: %zu (Mask: 0x%zx)\n", handle->shm_fd, size, mask);
    __ufifo_log("Ctrl fd: %d, Max Users: %zu, Num Users: %zu\n",
                handle->ctrl_fd,
                handle->ctrl->max_users,
                handle->ctrl->num_users);

    __ufifo_log("Data Mode: %s\n", __ufifo_is_shared(handle) ? "SHARED" : "SOLE");

    ufifo_version_t lib_ver = { 0 };
    ufifo_get_version_info(NULL, &lib_ver);
    __ufifo_log("Lib Version: %u.%u.%u (%s)\n", lib_ver.major, lib_ver.minor, lib_ver.patch, lib_ver.version);

    ufifo_version_t shm_ver = { 0 };
    ufifo_get_version_info(handle, &shm_ver);
    __ufifo_log("Shm Version: %u.%u.%u (%s)\n", shm_ver.major, shm_ver.minor, shm_ver.patch, shm_ver.version);

    const char *lock_modes[] = { "NONE", "THREAD", "PROCESS" };
    const char *lock_str = (handle->ctrl->lock < UFIFO_LOCK_MAX) ? lock_modes[handle->ctrl->lock] : "UNKNOWN";
    __ufifo_log("Lock Mode: %s\n", lock_str);

    __ufifo_log("Pointers: in = %zu (offset: %zu), out = %zu (offset: %zu)\n", in, in & mask, out, out & mask);

    /* Futex and io_uring ring info */
    __ufifo_log("Futex Tx: %u (waiters: %d), Futex Rx: %u (waiters: %d)\n",
                handle->ctrl->futex_tx,
                handle->ctrl->tx_waiters,
                __ufifo_rx_ctrl(handle)->futex_rx,
                __ufifo_rx_ctrl(handle)->rx_waiters);
    __ufifo_log("Ring Rx fd: %d, Ring Tx fd: %d\n", handle->rx_ring_fd, handle->tx_ring_fd);

    for (size_t i = 0; i < handle->ctrl->max_users; i++) {
        if (READ_ONCE(&handle->ctrl->users[i].active)) {
            size_t u_out = READ_ONCE(&handle->ctrl->users[i].out);
            unsigned int pid = handle->ctrl->users[i].pid;
            __ufifo_log("  User[%zu]: pid = %d, out = %zu (offset: %zu)\n", i, pid, u_out, u_out & mask);
        }
    }
    __ufifo_log("=========================\n");

    __ufifo_ctrl_unlock(handle);
}

const char *ufifo_get_version(void)
{
#ifndef UFIFO_VERSION
#define UFIFO_VERSION "unknown"
#endif
    return UFIFO_VERSION;
}

int ufifo_get_version_info(ufifo_t *handle, ufifo_version_t *ver)
{
#ifndef UFIFO_VERSION_MAJOR
#define UFIFO_VERSION_MAJOR 0
#endif
#ifndef UFIFO_VERSION_MINOR
#define UFIFO_VERSION_MINOR 0
#endif
#ifndef UFIFO_VERSION_PATCH
#define UFIFO_VERSION_PATCH 0
#endif
    if (ver == NULL) {
        return -EINVAL;
    }

    if (handle == NULL) {
        ver->major = UFIFO_VERSION_MAJOR;
        ver->minor = UFIFO_VERSION_MINOR;
        ver->patch = UFIFO_VERSION_PATCH;
        snprintf(ver->version, sizeof(ver->version), "%s", ufifo_get_version());
        return 0;
    }

    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    memcpy(ver, &handle->ctrl->ver, sizeof(*ver));
    return 0;
}

size_t ufifo_size(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle, 0);
    return handle->kfifo.mask + 1;
}

size_t ufifo_len(ufifo_t *handle)
{
    size_t len;
    UFIFO_CHECK_HANDLE(handle, 0);

    __ufifo_data_lock(handle);
    len = READ_ONCE(handle->kfifo.in) - READ_ONCE(handle->kfifo.out);
    __ufifo_data_unlock(handle);

    return len;
}

static size_t __ufifo_peek_tag(ufifo_t *handle, size_t offset)
{
    size_t ret = 0;

    if (handle->hook.rectag) {
        offset &= handle->kfifo.mask;
        ret = handle->hook.rectag(handle->shm_mem + offset, handle->kfifo.mask - offset + 1, handle->shm_mem);
    }

    return ret;
}

static int __ufifo_seek_tag(ufifo_t *handle, uint32_t tag, bool newest)
{
    int ret = -ESPIPE;
    size_t len, tmp;
    size_t target_pos = 0;
    bool found = false;

    __ufifo_data_lock(handle);
    tmp = READ_ONCE(handle->kfifo.out);
    size_t in_val = READ_ONCE(handle->kfifo.in);
    while (tmp != in_val) {
        len = __ufifo_peek_len(handle, tmp, in_val);
        if (len == 0)
            break;
        if (__ufifo_peek_tag(handle, tmp) == tag) {
            found = true;
            target_pos = tmp;
            if (!newest)
                break;
        }
        tmp += len;
    }

    if (found) {
        tmp = target_pos;
        ret = 0;
    } else {
        ret = -ESPIPE;
    }

    size_t old_out = READ_ONCE(handle->kfifo.out);
    smp_store_release(handle->kfifo.out, tmp);
    if (__ufifo_is_shared(handle)) {
        if (old_out == smp_load_acquire(&handle->ctrl->cached_min_out)) {
            __ufifo_update_cached_min_out(handle);
        }
    }
    __ufifo_notify_writers(handle);

    __ufifo_data_unlock(handle);
    return ret;
}

int ufifo_oldest(ufifo_t *handle, uint32_t tag)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_seek_tag(handle, tag, false);
}

int ufifo_newest(ufifo_t *handle, uint32_t tag)
{
    UFIFO_CHECK_HANDLE(handle, -EINVAL);
    return __ufifo_seek_tag(handle, tag, true);
}
