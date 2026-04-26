#include "ufifo_internal.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

void ufifo_dump(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE(handle);
    __ufifo_ctrl_lock(handle);

    unsigned int mask = *handle->kfifo.mask;
    unsigned int size = mask + 1;
    unsigned int in = READ_ONCE(handle->kfifo.in);
    unsigned int out = READ_ONCE(handle->kfifo.out);

    printf("=== ufifo_dump: %s ===\n", handle->name);
    printf("Shm fd: %d, Size: %u (Mask: 0x%x)\n", handle->shm_fd, size, mask);
    printf("Ctrl fd: %d, Max Users: %u, Num Users: %u\n",
           handle->ctrl_fd,
           handle->ctrl->max_users,
           handle->ctrl->num_users);

    printf("Data Mode: %s\n", __ufifo_is_shared(handle) ? "SHARED" : "SOLE");

    ufifo_version_t lib_ver = { 0 };
    ufifo_get_version_info(NULL, &lib_ver);
    printf("Lib Version: %u.%u.%u (%s)\n", lib_ver.major, lib_ver.minor, lib_ver.patch, lib_ver.version);

    ufifo_version_t shm_ver = { 0 };
    ufifo_get_version_info(handle, &shm_ver);
    printf("Shm Version: %u.%u.%u (%s)\n", shm_ver.major, shm_ver.minor, shm_ver.patch, shm_ver.version);

    const char *lock_modes[] = { "NONE", "THREAD", "PROCESS" };
    const char *lock_str = (handle->ctrl->lock < UFIFO_LOCK_MAX) ? lock_modes[handle->ctrl->lock] : "UNKNOWN";
    printf("Lock Mode: %s\n", lock_str);

    printf("Pointers: in = %u (offset: %u), out = %u (offset: %u)\n", in, in & mask, out, out & mask);

    // fd epoll info
    printf("Rx Efd: %d, Tx Efd: %d\n", handle->rx_efd, handle->tx_efd);

    unsigned int i;
    ufifo_for_each_active_user(handle, i) {
        unsigned int u_out = READ_ONCE(&handle->ctrl->users[i].out);
        printf("  User[%u]: pid = %d, out = %u (offset: %u)\n", i, handle->ctrl->users[i].pid, u_out, u_out & mask);
    }
    printf("=========================\n");

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

