#include "ufifo_internal.h"
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "utils.h"

/* epoll notification state machine: IDLE → REGISTERED → PENDING → REGISTERED */
enum {
    UFIFO_EFD_IDLE = 0,       /* no epoll fd registered */
    UFIFO_EFD_REGISTERED = 1, /* epoll fd registered, no pending notification */
    UFIFO_EFD_PENDING = 2,    /* epoll fd registered, notification sent but not yet drained */
};

/* Process-global sender socket for UDS notifications (lazy init) */
static int __ufifo_sender_fd = -1;
static pthread_once_t __ufifo_sender_once = PTHREAD_ONCE_INIT;

static void __ufifo_sender_init(void)
{
    __ufifo_sender_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

static int __ufifo_get_sender_fd(void)
{
    pthread_once(&__ufifo_sender_once, __ufifo_sender_init);
    return __ufifo_sender_fd;
}

static socklen_t __ufifo_notify_addr(const char *name, unsigned int user_id, struct sockaddr_un *addr, int is_rx)
{
    const char *fmt = "ufifo_%s_%s_%u";

    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    int n = snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, fmt, is_rx ? "rx" : "tx", name, user_id);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

void __ufifo_efd_notify_rx(ufifo_t *handle)
{
    int sfd = __ufifo_get_sender_fd();
    if (sfd < 0)
        return;

    unsigned int i;
    struct sockaddr_un addr;
    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (!READ_ONCE(&handle->ctrl->users[i].active))
            continue;

        unsigned int state = smp_load_acquire(&handle->ctrl->users[i].efd_rx_flag);
        if (state != UFIFO_EFD_REGISTERED)
            continue; /* IDLE → skip; PENDING → coalesce */

        smp_store_release(&handle->ctrl->users[i].efd_rx_flag, UFIFO_EFD_PENDING);
        socklen_t len = __ufifo_notify_addr(handle->name, i, &addr, 1);
        sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, len);
    }
}

void __ufifo_efd_notify_tx(ufifo_t *handle)
{
    int state = smp_load_acquire(&handle->ctrl->efd_tx_flag);
    if (state != UFIFO_EFD_REGISTERED)
        return; /* IDLE → no one registered; PENDING → coalesce */

    smp_store_release(&handle->ctrl->efd_tx_flag, UFIFO_EFD_PENDING);

    int sfd = __ufifo_get_sender_fd();
    if (sfd < 0)
        return;

    unsigned int i;
    struct sockaddr_un addr;
    for (i = 0; i < handle->ctrl->max_users; i++) {
        if (!READ_ONCE(&handle->ctrl->users[i].active))
            continue;
        socklen_t len = __ufifo_notify_addr(handle->name, i, &addr, 0);
        sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, len);
    }
}

static int __ufifo_get_efd(ufifo_t *handle, int is_rx)
{
    int ret_fd;
    __ufifo_ctrl_lock(handle);

    int *efd = is_rx ? &handle->rx_efd : &handle->tx_efd;
    int *efd_flags;
    struct sockaddr_un addr;
    socklen_t addr_len;

    if (*efd >= 0) {
        ret_fd = *efd;
        goto end;
    }

    *efd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (*efd < 0) {
        ret_fd = -1;
        goto end;
    }

    addr_len = __ufifo_notify_addr(handle->name, handle->user_id, &addr, is_rx);
    if (bind(*efd, (struct sockaddr *)&addr, addr_len) < 0) {
        close(*efd);
        *efd = -1;
        ret_fd = -1;
        goto end;
    }

    /* Mark this user as epoll-registered in shared memory */
    efd_flags = is_rx ? &handle->ctrl->users[handle->user_id].efd_rx_flag : &handle->ctrl->efd_tx_flag;
    smp_store_release(efd_flags, UFIFO_EFD_REGISTERED);

    /* Pre-arm condition: check if we should send a notification to self */
    int should_arm = 0;
    if (is_rx) {
        if (READ_ONCE(handle->kfifo.in) != READ_ONCE(handle->kfifo.out))
            should_arm = 1;
    } else {
        unsigned int len = READ_ONCE(handle->kfifo.in) - READ_ONCE(handle->kfifo.out);
        unsigned int unused = *handle->kfifo.mask + 1 - len;
        if (unused > 0)
            should_arm = 1;
    }

    if (should_arm) {
        int sfd = __ufifo_get_sender_fd();
        if (sfd >= 0) {
            sendto(sfd, "1", 1, MSG_DONTWAIT, (struct sockaddr *)&addr, addr_len);
            /* Pre-arm also sets pending since we just sent a notification */
            smp_store_release(efd_flags, UFIFO_EFD_PENDING);
        }
    }

    ret_fd = *efd;

end:
    __ufifo_ctrl_unlock(handle);
    return ret_fd;
}

int ufifo_get_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get_efd(handle, 1);
}

int ufifo_get_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_get_efd(handle, 0);
}

static int __ufifo_drain_efd(int fd, int *efd_flags)
{
    if (fd < 0)
        return -EINVAL;

    char buf[128];
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
    }

    /* Transition: PENDING → REGISTERED (re-arm for next notification) */
    smp_store_release(efd_flags, UFIFO_EFD_REGISTERED);
    return 0;
}

int ufifo_drain_rx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_drain_efd(handle->rx_efd, &handle->ctrl->users[handle->user_id].efd_rx_flag);
}

int ufifo_drain_tx_fd(ufifo_t *handle)
{
    UFIFO_CHECK_HANDLE_FUNC(handle);
    return __ufifo_drain_efd(handle->tx_efd, &handle->ctrl->efd_tx_flag);
}
