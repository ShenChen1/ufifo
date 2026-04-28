#include "ufifo_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/*  Abstract namespace address                                         */
/* ------------------------------------------------------------------ */

static socklen_t __ufifo_broker_addr(const char *name, struct sockaddr_un *addr)
{
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0'; /* abstract namespace */
    int n = snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "ufifo_%s_broker", name);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

/* ------------------------------------------------------------------ */
/*  SCM_RIGHTS helpers                                                 */
/* ------------------------------------------------------------------ */

static int __ufifo_send_fds(int sock, const int *fds, unsigned int nfds)
{
    char dummy = 'F';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };

    size_t cmsg_space = CMSG_SPACE(nfds * sizeof(int));
    char *cmsg_buf = calloc(1, cmsg_space);
    if (!cmsg_buf)
        return -ENOMEM;

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = cmsg_space,
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(nfds * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, nfds * sizeof(int));

    int ret = sendmsg(sock, &msg, 0);
    free(cmsg_buf);
    return ret < 0 ? -errno : 0;
}

static int __ufifo_recv_fds(int sock, int *fds, unsigned int nfds)
{
    char dummy;
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };

    size_t cmsg_space = CMSG_SPACE(nfds * sizeof(int));
    char *cmsg_buf = calloc(1, cmsg_space);
    if (!cmsg_buf)
        return -ENOMEM;

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = cmsg_space,
    };

    int ret = recvmsg(sock, &msg, 0);
    if (ret < 0) {
        free(cmsg_buf);
        return -errno;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        free(cmsg_buf);
        return -EPROTO;
    }

    memcpy(fds, CMSG_DATA(cmsg), nfds * sizeof(int));
    free(cmsg_buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Broker daemon loop (runs in forked child)                          */
/*                                                                     */
/*  Design constraints for stability:                                  */
/*   - No mutex usage (async-signal-safe after fork)                   */
/*   - Pre-allocate all buffers before the loop                        */
/*   - Only syscalls: poll, accept4, sendmsg, close, shm_open         */
/* ------------------------------------------------------------------ */

/*
 * Broker daemon context: all data the daemon needs, copied before fork.
 * The daemon must NOT access the parent's ufifo_t handle.
 */
typedef struct {
    int listener_fd;
    int *fds_to_send;       /* packed: [efd_wr, efd_rd_all[0..N-1]] */
    unsigned int total_fds; /* 1 + max_users */
    char shm_name[128];
} broker_ctx_t;

#define BROKER_POLL_INTERVAL_MS 2000

static void __ufifo_broker_daemon(broker_ctx_t *ctx)
{
    setsid();

    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > STDERR_FILENO)
            close(null_fd);
    }

    while (1) {
        struct pollfd pfd = { .fd = ctx->listener_fd, .events = POLLIN };
        int ready = poll(&pfd, 1, BROKER_POLL_INTERVAL_MS);

        if (ready > 0 && (pfd.revents & POLLIN)) {
            int client = accept4(ctx->listener_fd, NULL, NULL, SOCK_CLOEXEC);
            if (client >= 0) {
                /* Ignore send errors: client may have disconnected */
                __ufifo_send_fds(client, ctx->fds_to_send, ctx->total_fds);
                close(client);
            }
        }

        /* Periodic liveness check: exit when shm is destroyed */
        int probe = shm_open(ctx->shm_name, O_RDONLY, 0);
        if (probe < 0) {
            if (errno == ENOENT)
                break; /* shm destroyed → graceful exit */
            /* Other errors (e.g. permission): stay alive, be conservative */
        } else {
            close(probe);
        }
    }

    /* Cleanup: close listener + all eventfds */
    close(ctx->listener_fd);
    unsigned int i;
    for (i = 0; i < ctx->total_fds; i++)
        close(ctx->fds_to_send[i]);
}

/* ------------------------------------------------------------------ */
/*  Broker start (double-fork)                                         */
/* ------------------------------------------------------------------ */

static int __ufifo_broker_fork(ufifo_t *handle, int listener_fd)
{
    unsigned int total_fds = 1 + handle->efd_count;

    /* Pre-pack fd array on parent's stack; child inherits a copy */
    int *fds_to_send = malloc(total_fds * sizeof(int));
    if (!fds_to_send)
        return -ENOMEM;

    fds_to_send[0] = handle->efd_wr;
    memcpy(fds_to_send + 1, handle->efd_rd_all, handle->efd_count * sizeof(int));

    broker_ctx_t ctx = {
        .listener_fd = listener_fd,
        .fds_to_send = fds_to_send,
        .total_fds = total_fds,
    };
    strncpy(ctx.shm_name, handle->name, sizeof(ctx.shm_name) - 1);

    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        free(fds_to_send);
        return -err;
    }

    if (pid == 0) {
        /* First child: double-fork to orphan the daemon */
        pid_t pid2 = fork();
        if (pid2 > 0)
            _exit(0); /* first child exits immediately */
        if (pid2 < 0)
            _exit(1);

        /* Grandchild: actual broker daemon */

        /* Close fds the broker doesn't need */
        close(handle->shm_fd);
        close(handle->ctrl_fd);
        /* Note: shm_mem/ctrl are mmap'd, child has COW copies — harmless */

        __ufifo_broker_daemon(&ctx);
        /* ctx.fds_to_send is freed implicitly by _exit */
        _exit(0);
    }

    /* Parent: wait for first child (returns almost immediately) */
    waitpid(pid, NULL, 0);

    /* Parent no longer needs the listener (broker owns it) */
    close(listener_fd);
    free(fds_to_send);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Broker start: create listener + fork                               */
/* ------------------------------------------------------------------ */

int __ufifo_broker_start(ufifo_t *handle)
{
    struct sockaddr_un addr;
    socklen_t addr_len;
    int listener_fd;
    int ret;

    listener_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listener_fd < 0)
        return -errno;

    addr_len = __ufifo_broker_addr(handle->name, &addr);

    /*
     * bind() to abstract namespace is atomic: only one process can bind
     * to the same address. This serves as the "broker election" lock.
     */
    if (bind(listener_fd, (struct sockaddr *)&addr, addr_len) < 0) {
        int err = errno;
        close(listener_fd);
        return -err; /* EADDRINUSE = someone else won */
    }

    if (listen(listener_fd, 8) < 0) {
        int err = errno;
        close(listener_fd);
        return -err;
    }

    ret = __ufifo_broker_fork(handle, listener_fd);
    if (ret < 0) {
        close(listener_fd);
        return ret;
    }

    handle->is_broker_owner = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Broker connect: ATTACH process receives eventfds                   */
/* ------------------------------------------------------------------ */

static int __ufifo_broker_connect(ufifo_t *handle)
{
    struct sockaddr_un addr;
    socklen_t addr_len;
    unsigned int total_fds = 1 + handle->ctrl->max_users;
    int ret;

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0)
        return -errno;

    addr_len = __ufifo_broker_addr(handle->name, &addr);

    /* Retry with brief backoff (broker may be starting up) */
    int attempts = 50;
    while (attempts-- > 0) {
        ret = connect(sock, (struct sockaddr *)&addr, addr_len);
        if (ret == 0)
            break;
        if (errno != ECONNREFUSED && errno != ENOENT) {
            close(sock);
            return -errno;
        }
        usleep(10000); /* 10ms */
    }
    if (ret < 0) {
        close(sock);
        return -ETIMEDOUT;
    }

    int *fds = calloc(total_fds, sizeof(int));
    if (!fds) {
        close(sock);
        return -ENOMEM;
    }

    ret = __ufifo_recv_fds(sock, fds, total_fds);
    close(sock);

    if (ret < 0) {
        free(fds);
        return ret;
    }

    /* Unpack: [efd_wr, efd_rd_all[0], efd_rd_all[1], ...] */
    handle->efd_wr = fds[0];
    handle->efd_count = handle->ctrl->max_users;
    handle->efd_rd_all = malloc(handle->efd_count * sizeof(int));
    if (!handle->efd_rd_all) {
        unsigned int i;
        for (i = 0; i < total_fds; i++)
            close(fds[i]);
        free(fds);
        return -ENOMEM;
    }
    memcpy(handle->efd_rd_all, fds + 1, handle->efd_count * sizeof(int));
    free(fds);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Unified eventfd acquisition (used by both ALLOC and ATTACH)        */
/* ------------------------------------------------------------------ */

int __ufifo_acquire_eventfds(ufifo_t *handle, int is_alloc)
{
    int ret;

    /* Step 1: try connecting to an existing broker (ATTACH only) */
    if (!is_alloc) {
        ret = __ufifo_broker_connect(handle);
        if (ret == 0)
            goto set_rd;
    }

    /* Step 2: no broker → bootstrap: create eventfds + fork broker */
    ret = __ufifo_efd_create_all(handle, handle->ctrl->max_users);
    if (ret < 0)
        return ret;

    ret = __ufifo_broker_start(handle);
    if (ret == -EADDRINUSE) {
        /*
         * Another process won the broker election race.
         * Discard our eventfds and connect to the winner's broker.
         */
        __ufifo_efd_close_all(handle);
        ret = __ufifo_broker_connect(handle);
        if (ret < 0)
            return ret;
    } else if (ret < 0) {
        __ufifo_efd_close_all(handle);
        return ret;
    }

set_rd:
    handle->efd_rd = __ufifo_is_shared(handle) ? handle->efd_rd_all[handle->user_id] : handle->efd_rd_all[0];
    return 0;
}

/* ------------------------------------------------------------------ */
/*  eventfd creation and cleanup                                       */
/* ------------------------------------------------------------------ */

int __ufifo_efd_create_all(ufifo_t *handle, unsigned int max_users)
{
    unsigned int i;

    handle->efd_wr = __ufifo_efd_create();
    if (handle->efd_wr < 0)
        return -errno;

    handle->efd_count = max_users;
    handle->efd_rd_all = calloc(max_users, sizeof(int));
    if (!handle->efd_rd_all) {
        close(handle->efd_wr);
        handle->efd_wr = -1;
        return -ENOMEM;
    }

    for (i = 0; i < max_users; i++) {
        handle->efd_rd_all[i] = __ufifo_efd_create();
        if (handle->efd_rd_all[i] < 0) {
            int err = errno;
            unsigned int j;
            for (j = 0; j < i; j++)
                close(handle->efd_rd_all[j]);
            free(handle->efd_rd_all);
            handle->efd_rd_all = NULL;
            close(handle->efd_wr);
            handle->efd_wr = -1;
            return -err;
        }
    }

    return 0;
}

void __ufifo_efd_close_all(ufifo_t *handle)
{
    if (handle->efd_wr >= 0) {
        close(handle->efd_wr);
        handle->efd_wr = -1;
    }

    if (handle->efd_rd_all) {
        unsigned int i;
        for (i = 0; i < handle->efd_count; i++) {
            if (handle->efd_rd_all[i] >= 0)
                close(handle->efd_rd_all[i]);
        }
        free(handle->efd_rd_all);
        handle->efd_rd_all = NULL;
    }
    handle->efd_rd = -1;
}
