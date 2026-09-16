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
static int __ufifo_recv_fds(int sock, int *fds, size_t nfds)
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
/*  Broker start (double-fork & exec)                                  */
/* ------------------------------------------------------------------ */

#include <dirent.h>
#include <limits.h>

static int get_broker_path(char *path, size_t size)
{
    const char *env_path = getenv("UFIFO_BROKER_PATH");
    if (env_path) {
        snprintf(path, size, "%s", env_path);
        return 0;
    }
    ssize_t len = readlink("/proc/self/exe", path, size - 1);
    if (len > 0) {
        path[len] = '\0';
        char *last_slash = strrchr(path, '/');
        if (last_slash) {
            *(last_slash + 1) = '\0';
            strncat(path, "ufifo-broker", size - strlen(path) - 1);
            if (access(path, X_OK) == 0) {
                return 0;
            }
        }
    }
    snprintf(path, size, "ufifo-broker");
    return 0;
}

static bool fd_in_set(int fd, int listener_fd, const int *fds, size_t nfds)
{
    if (fd == listener_fd)
        return true;
    for (size_t i = 0; i < nfds; i++) {
        if (fd == fds[i])
            return true;
    }
    return false;
}

/*
 * Close all fds except listener_fd and keep_fds[].
 * Also clears O_CLOEXEC on kept fds so they survive exec.
 */
static void close_inherited_fds(int listener_fd, const int *keep_fds, size_t nfds)
{
    fcntl(listener_fd, F_SETFD, 0);
    for (size_t i = 0; i < nfds; i++)
        fcntl(keep_fds[i], F_SETFD, 0);

    DIR *dir = opendir("/proc/self/fd");
    if (dir) {
        int dir_fd = dirfd(dir);
        struct dirent *dp;
        while ((dp = readdir(dir)) != NULL) {
            if (dp->d_name[0] == '.')
                continue;
            int fd = atoi(dp->d_name);
            if (fd != dir_fd && !fd_in_set(fd, listener_fd, keep_fds, nfds))
                close(fd);
        }
        closedir(dir);
        return;
    }
    /* Fallback when /proc is unavailable */
    for (int fd = 3; fd < 1024; fd++) {
        if (!fd_in_set(fd, listener_fd, keep_fds, nfds))
            close(fd);
    }
}

/* Build argv: ["ufifo-broker", shm_name, listener_fd, fd0, fd1, ..., NULL] */
static char **build_broker_argv(const char *name, int listener_fd, const int *fds, size_t nfds)
{
    char **args = malloc((4 + nfds) * sizeof(char *));
    if (!args)
        return NULL;

    char buf[32];
    args[0] = strdup("ufifo-broker");
    args[1] = strdup(name);
    snprintf(buf, sizeof(buf), "%d", listener_fd);
    args[2] = strdup(buf);
    for (size_t i = 0; i < nfds; i++) {
        snprintf(buf, sizeof(buf), "%d", fds[i]);
        args[3 + i] = strdup(buf);
    }
    args[3 + nfds] = NULL;
    return args;
}

static int __ufifo_broker_fork(ufifo_t *handle, int listener_fd)
{
    size_t total_fds = 1 + handle->efd_count;

    int *fds_to_send = malloc(total_fds * sizeof(int));
    if (!fds_to_send)
        return -ENOMEM;

    fds_to_send[0] = handle->efd_wr;
    memcpy(fds_to_send + 1, handle->efd_rd_all, handle->efd_count * sizeof(int));

    char broker_path[PATH_MAX];
    get_broker_path(broker_path, sizeof(broker_path));

    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        free(fds_to_send);
        return -err;
    }

    if (pid == 0) {
        pid_t pid2 = fork();
        if (pid2 > 0)
            _exit(0);
        if (pid2 < 0)
            _exit(1);

        /* Grandchild: sanitize fds and exec broker */
        close_inherited_fds(listener_fd, fds_to_send, total_fds);
        char **args = build_broker_argv(handle->name, listener_fd, fds_to_send, total_fds);
        if (!args)
            _exit(1);
        execvp(broker_path, args);
        _exit(1);
    }

    waitpid(pid, NULL, 0);
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

    handle->is_broker_owner = true;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Broker connect: ATTACH process receives eventfds                   */
/* ------------------------------------------------------------------ */

static int __ufifo_broker_connect(ufifo_t *handle)
{
    struct sockaddr_un addr;
    socklen_t addr_len;
    size_t rx_slot_count = __ufifo_rx_slot_count(handle);
    size_t total_fds = 1 + rx_slot_count;
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
    handle->efd_count = rx_slot_count;
    handle->efd_rd_all = malloc(handle->efd_count * sizeof(int));
    if (!handle->efd_rd_all) {
        for (size_t i = 0; i < total_fds; i++)
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

int __ufifo_acquire_eventfds(ufifo_t *handle, bool is_alloc)
{
    int ret;

    /* Step 1: try connecting to an existing broker (ATTACH only) */
    if (!is_alloc) {
        ret = __ufifo_broker_connect(handle);
        if (ret == 0)
            goto set_rd;
    }

    /* Step 2: no broker → bootstrap: create eventfds + fork broker */
    ret = __ufifo_efd_create_all(handle, __ufifo_rx_slot_count(handle));
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
    } else {
        __atomic_add_fetch(&handle->ctrl->broker_gen, 1, __ATOMIC_RELEASE);
    }

set_rd:
    handle->efd_rd = handle->efd_rd_all[__ufifo_rx_slot_id(handle)];
    return 0;
}

/* ------------------------------------------------------------------ */
/*  eventfd creation and cleanup                                       */
/* ------------------------------------------------------------------ */

int __ufifo_efd_create_all(ufifo_t *handle, size_t count)
{
    handle->efd_wr = __ufifo_efd_create();
    if (handle->efd_wr < 0)
        return -errno;

    handle->efd_count = count;
    handle->efd_rd_all = calloc(count, sizeof(int));
    if (!handle->efd_rd_all) {
        close(handle->efd_wr);
        handle->efd_wr = -1;
        return -ENOMEM;
    }

    for (size_t i = 0; i < count; i++) {
        handle->efd_rd_all[i] = __ufifo_efd_create();
        if (handle->efd_rd_all[i] < 0) {
            int err = errno;
            for (size_t j = 0; j < i; j++)
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
        for (size_t i = 0; i < handle->efd_count; i++) {
            if (handle->efd_rd_all[i] >= 0)
                close(handle->efd_rd_all[i]);
        }
        free(handle->efd_rd_all);
        handle->efd_rd_all = NULL;
    }
    handle->efd_rd = -1;
}

void __ufifo_broker_wake_to_exit(const char *name)
{
    struct sockaddr_un addr;
    socklen_t addr_len = __ufifo_broker_addr(name, &addr);

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0)
        return;

    /*
     * Connect to the broker. The broker will send its FDs, then check
     * shm liveness. If shm is gone, it closes its listener socket (releasing
     * the abstract address) BEFORE closing this client connection.
     * Thus, reading until EOF deterministically waits for the broker
     * to release the address, eliminating the need for polling.
     */
    if (connect(s, (struct sockaddr *)&addr, addr_len) == 0) {
        struct pollfd pfd = { .fd = s, .events = POLLIN };
        char buf[16];
        while (1) {
            int r = poll(&pfd, 1, 5000);
            if (r <= 0)
                break;
            ssize_t n = read(s, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            } else if (n == 0) {
                break;
            }
        }
    }
    close(s);
}
