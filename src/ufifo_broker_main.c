#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BROKER_POLL_INTERVAL_MS 2000

static int __ufifo_send_fds_prealloc(int sock, const int *fds, size_t nfds, char *buf, size_t buf_size)
{
    char dummy = 'F';
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };

    memset(buf, 0, buf_size);
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = buf,
        .msg_controllen = buf_size,
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(nfds * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, nfds * sizeof(int));

    int ret = sendmsg(sock, &msg, 0);
    return ret < 0 ? -errno : 0;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: ufifo-broker <shm_name> <listener_fd> <fds...>\n");
        return 1;
    }

    const char *shm_name = argv[1];
    int listener_fd = atoi(argv[2]);
    size_t total_fds = argc - 3;

    int *fds_to_send = malloc(total_fds * sizeof(int));
    if (!fds_to_send)
        return 1;

    for (size_t i = 0; i < total_fds; i++) {
        fds_to_send[i] = atoi(argv[3 + i]);
    }

    size_t cmsg_buf_size = CMSG_SPACE(total_fds * sizeof(int));
    char *cmsg_buf = calloc(1, cmsg_buf_size);
    if (!cmsg_buf) {
        free(fds_to_send);
        return 1;
    }

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
        struct pollfd pfd = { .fd = listener_fd, .events = POLLIN };
        int ready = poll(&pfd, 1, BROKER_POLL_INTERVAL_MS);

        int client = -1;
        if (ready > 0 && (pfd.revents & POLLIN)) {
            client = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
            if (client >= 0) {
                __ufifo_send_fds_prealloc(client, fds_to_send, total_fds, cmsg_buf, cmsg_buf_size);
            }
        }

        int probe = shm_open(shm_name, O_RDONLY, 0);
        if (probe < 0) {
            if (errno == ENOENT) {
                if (listener_fd >= 0) {
                    close(listener_fd);
                    listener_fd = -1;
                }
                if (client >= 0)
                    close(client);
                break;
            }
        } else {
            close(probe);
        }

        if (client >= 0)
            close(client);
    }

    if (listener_fd >= 0)
        close(listener_fd);
    for (size_t i = 0; i < total_fds; i++)
        close(fds_to_send[i]);

    free(fds_to_send);
    free(cmsg_buf);

    return 0;
}
