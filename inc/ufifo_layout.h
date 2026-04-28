#ifndef UFIFO_LAYOUT_H
#define UFIFO_LAYOUT_H

#include <pthread.h>

#include "ufifo.h"

/* Per-user control data (stored in shared memory) */
typedef struct {
    pid_t pid;
    unsigned int active;
    unsigned int out;
    int rx_waiters;    /* count of threads blocked in poll() waiting for data */
    int epoll_armed;   /* 1 = epoll listener waiting; 0 = already notified or idle */
} ufifo_sub_ctrl_t;

/* Global FIFO control data (stored in shared memory) */
typedef struct {
    ufifo_version_t ver;
    unsigned int init_done; /* 0 = initializing, 1 = ready (atomic) */

    unsigned int in;
    unsigned int mask;

    ufifo_lock_e lock;
    pthread_mutex_t ctrl_mutex; /* always active: protects control data */
    pthread_mutex_t data_mutex; /* governed by ufifo_lock_e: protects index movement */

    int tx_waiters;      /* count of threads blocked in poll() waiting for space */
    int epoll_tx_armed;  /* 1 = epoll listener waiting; 0 = already notified or idle */

    ufifo_data_mode_e data_mode;
    unsigned int max_users;
    unsigned int num_users;
    ufifo_sub_ctrl_t users[];
} ufifo_ctrl_t;

#endif /* UFIFO_LAYOUT_H */
