#include "ufifo.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define FIFO_NAME "epoll_shared_fifo"
#define NUM_CLIENTS 3
#define MSG_COUNT 5

// Context for writer thread
typedef struct {
    ufifo_t *fifo;
} writer_ctx_t;

// Writer thread function: writes messages into the shared FIFO
static void *writer_thread_func(void *arg)
{
    writer_ctx_t *ctx = (writer_ctx_t *)arg;

    for (int i = 0; i < MSG_COUNT; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Message %d", i);

        // Put message into FIFO
        unsigned int written = ufifo_put(ctx->fifo, msg, strlen(msg) + 1);
        if (written > 0) {
            printf("[Writer] Sent: '%s'\n", msg);
            // In shared data mode, the writer must consume its own produced message
            // to advance its read pointer, otherwise the buffer will fill up.
            char dummy[64];
            ufifo_get(ctx->fifo, dummy, sizeof(dummy));
        }

        usleep(1000000); // Wait 1 second before sending the next message
    }

    return NULL;
}

int main(void)
{
    printf("=== ufifo epoll shared consumers ===\n");

    ufifo_t *writer_fifo = NULL;
    ufifo_init_t alloc_init = { 0 };
    alloc_init.opt = UFIFO_OPT_ALLOC;
    alloc_init.alloc.size = 1024;
    alloc_init.alloc.force = 1;
    alloc_init.alloc.lock = UFIFO_LOCK_THREAD;
    alloc_init.alloc.data_mode = UFIFO_DATA_SHARED; // Multicast mode
    alloc_init.alloc.max_users = NUM_CLIENTS + 1;   // 1 writer + 3 readers

    // 1. Alloc a fifo
    if (ufifo_open(FIFO_NAME, &alloc_init, &writer_fifo) != 0) {
        perror("Failed to alloc ufifo");
        return 1;
    }

    ufifo_t *readers[NUM_CLIENTS] = { NULL };
    ufifo_init_t attach_init = { 0 };
    attach_init.opt = UFIFO_OPT_ATTACH;

    // 2. Create an epoll
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1 failed");
        return 1;
    }

    // 1. (cont'd) Attach 3 times and
    // 3. Add the 3 attached fds into epoll
    for (int i = 0; i < NUM_CLIENTS; i++) {
        if (ufifo_open(FIFO_NAME, &attach_init, &readers[i]) != 0) {
            fprintf(stderr, "Failed to attach ufifo %d\n", i);
            return 1;
        }

        int fd = ufifo_get_rx_fd(readers[i]);
        if (fd < 0) {
            fprintf(stderr, "Failed to get fd for reader %d\n", i);
            return 1;
        }

        struct epoll_event ev = { 0 };
        ev.events = EPOLLIN;
        ev.data.u32 = i;

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
            perror("epoll_ctl ADD failed");
            return 1;
        }
    }

    // 4. Start writer thread
    writer_ctx_t ctx = { .fifo = writer_fifo };
    pthread_t writer_thread;
    if (pthread_create(&writer_thread, NULL, writer_thread_func, &ctx) != 0) {
        perror("Failed to create writer thread");
        return 1;
    }

    // 5. Loop waiting for epoll events
    int expected_msgs = NUM_CLIENTS * MSG_COUNT;
    int received_msgs = 0;
    struct epoll_event events[NUM_CLIENTS];

    while (received_msgs < expected_msgs) {
        struct timeval start, end;
        gettimeofday(&start, NULL);
        printf("[Main] Blocked on epoll_wait...\n");

        int nfds = epoll_wait(epfd, events, NUM_CLIENTS, 3000); // 3s timeout

        gettimeofday(&end, NULL);
        long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
        printf("[Main] epoll_wait returned %d after %ld ms\n", nfds, elapsed_ms);

        if (nfds < 0) {
            perror("epoll_wait error");
            break;
        }

        if (nfds == 0) {
            printf("[Main] Timeout waiting for events...\n");
            continue;
        }

        // 6. Receive data
        for (int i = 0; i < nfds; i++) {
            int client_id = events[i].data.u32;

            // Clear the wake-up signal from socket using library API
            int fd = ufifo_get_rx_fd(readers[client_id]);
            ufifo_drain_fd(readers[client_id], fd);

            char buf[64];
            while (ufifo_get(readers[client_id], buf, sizeof(buf)) > 0) {
                printf("[Reader %d] Got: '%s'\n", client_id, buf);
                received_msgs++;
            }
        }
    }

    pthread_join(writer_thread, NULL);

    // 7. Close epoll and fifo
    for (int i = 0; i < NUM_CLIENTS; i++) {
        if (readers[i]) {
            ufifo_close(readers[i]);
        }
    }
    close(epfd);
    ufifo_destroy(writer_fifo);

    printf("Done. Received %d / %d msgs.\n", received_msgs, expected_msgs);
    return 0;
}