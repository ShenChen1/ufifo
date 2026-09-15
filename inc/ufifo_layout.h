#ifndef UFIFO_LAYOUT_H
#define UFIFO_LAYOUT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "ufifo.h"

/*
 * Receive-slot control data (stored in shared memory).
 * users[0..max_users-1] are registered user slots.
 * In SOLE mode, users[max_users] is reserved for the global receive state.
 */
typedef struct {
    pid_t pid;
    bool active;
    size_t out;
    int32_t rx_waiters;  /* count of threads blocked in poll() waiting for data */
    int32_t epoll_armed; /* 1 = epoll listener waiting; 0 = already notified or idle */
} ufifo_sub_ctrl_t;

/* Global FIFO control data (stored in shared memory) */
typedef struct {
    ufifo_version_t ver;
    bool init_done; /* false = initializing, true = ready (atomic) */

    size_t in;
    size_t mask;
    size_t cached_min_out; /* O(1) cache for SHARED mode */

    ufifo_lock_e lock;
    pthread_mutex_t ctrl_mutex; /* always active: protects control data */
    pthread_mutex_t data_mutex; /* governed by ufifo_lock_e: protects index movement */

    int32_t tx_waiters;     /* count of threads blocked in poll() waiting for space */
    int32_t epoll_tx_armed; /* 1 = epoll listener waiting; 0 = already notified or idle */

    uint32_t broker_gen;

    ufifo_data_mode_e data_mode;
    size_t max_users;
    size_t num_users;
    ufifo_sub_ctrl_t users[];
} ufifo_ctrl_t;

#endif /* UFIFO_LAYOUT_H */
