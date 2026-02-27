#include "ufifo.h"
#include "utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define FIFO_SIZE 256
#define ITEMS_PER_FIFO 5

static const char *fifo_names[] = { "epoll_fifo_a", "epoll_fifo_b" };

/* Child process: attach to a FIFO and write data */
static void producer(const char *name, int id)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ATTACH;
    ufifo_t *fifo = NULL;

    if (ufifo_open((char *)name, &init, &fifo) < 0) {
        fprintf(stderr, "producer %d: attach to \"%s\" failed\n", id, name);
        _exit(1);
    }

    for (int i = 0; i < ITEMS_PER_FIFO; i++) {
        int val = id * 100 + i;
        usleep(100000 * (id + 1)); /* different write rates */
        ufifo_put(fifo, &val, sizeof(val));
        printf("  [producer %d pid=%d] put %d\n", id, getpid(), val);
    }

    ufifo_close(fifo);
    _exit(0);
}

int main(void)
{
    const int num_fifos = ARRAY_SIZE(fifo_names);
    ufifo_t *fifos[ARRAY_SIZE(fifo_names)] = { NULL };
    pid_t pids[ARRAY_SIZE(fifo_names)];
    int epfd, total = 0;
    const int expected = num_fifos * ITEMS_PER_FIFO;
    struct epoll_event ev, events[ARRAY_SIZE(fifo_names)];

    printf("=== ufifo epoll multiplexing (multi-process) ===\n");
    printf("parent pid=%d\n\n", getpid());

    /* Parent: create FIFOs */
    for (int i = 0; i < num_fifos; i++) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = FIFO_SIZE;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_PROCESS;
        init.alloc.max_users = 2;
        if (ufifo_open((char *)fifo_names[i], &init, &fifos[i]) < 0) {
            fprintf(stderr, "failed to create fifo %d\n", i);
            return 1;
        }
    }

    /* Create epoll and register FIFO fds */
    epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        return 1;
    }

    for (int i = 0; i < num_fifos; i++) {
        int fd = ufifo_get_fd(fifos[i]);
        if (fd < 0) {
            fprintf(stderr, "ufifo_get_fd failed for fifo %d\n", i);
            return 1;
        }
        ev.events = EPOLLIN;
        ev.data.u32 = i;
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
        printf("fifo[%d] \"%s\" → fd %d\n", i, fifo_names[i], fd);
    }
    printf("\n");

    /* Fork producer child processes */
    for (int i = 0; i < num_fifos; i++) {
        pids[i] = fork();
        if (pids[i] < 0) {
            perror("fork");
            return 1;
        }
        if (pids[i] == 0) {
            /* Child: close parent's epoll and fifo handles are COW */
            close(epfd);
            producer(fifo_names[i], i);
            /* not reached */
        }
    }

    /* Parent: epoll loop to consume from all FIFOs */
    while (total < expected) {
        int nfds = epoll_wait(epfd, events, num_fifos, 3000);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("epoll_wait");
            break;
        }
        if (nfds == 0) {
            printf("  (timeout, %d/%d received)\n", total, expected);
            continue;
        }
        for (int n = 0; n < nfds; n++) {
            int idx = events[n].data.u32;
            /* Drain notification socket */
            char buf[64];
            int fd = ufifo_get_fd(fifos[idx]);
            while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
            }
            /* Read all available data from this FIFO */
            int val;
            while (ufifo_get(fifos[idx], &val, sizeof(val)) > 0) {
                printf("  [consumer pid=%d] fifo[%d] got %d\n", getpid(), idx, val);
                total++;
            }
        }
    }

    printf("\ntotal received: %d/%d\n", total, expected);

    /* Wait for children */
    for (int i = 0; i < num_fifos; i++) {
        waitpid(pids[i], NULL, 0);
    }

    /* Cleanup */
    close(epfd);
    for (int i = 0; i < num_fifos; i++) {
        ufifo_destroy(fifos[i]);
    }

    printf("test %s\n", total == expected ? "passed" : "FAILED");
    return total == expected ? 0 : 1;
}
