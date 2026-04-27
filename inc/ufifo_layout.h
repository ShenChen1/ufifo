#ifndef UFIFO_LAYOUT_H
#define UFIFO_LAYOUT_H

#include <pthread.h>
#include <semaphore.h>

#include "ufifo.h"

typedef struct {
    pid_t pid;
    unsigned int active;

    unsigned int out;
    sem_t bsem_rd;
    int efd_rx_flag; /* per-user RX epoll state (IDLE/REGISTERED/PENDING) */
} ufifo_sub_ctrl_t;

typedef struct {
    ufifo_version_t ver;
    unsigned int init_done; /* 0 = initializing, 1 = ready (atomic) */

    unsigned int in;
    unsigned int mask;

    ufifo_lock_e lock;
    pthread_mutex_t ctrl_mutex; /* always active: protects control data */
    pthread_mutex_t data_mutex; /* governed by ufifo_lock_e: protects index movement */

    sem_t bsem_wr;
    int efd_tx_flag; /* global TX epoll state (IDLE/REGISTERED/PENDING) */

    ufifo_data_mode_e data_mode;
    unsigned int max_users;
    unsigned int num_users;
    ufifo_sub_ctrl_t users[];
} ufifo_ctrl_t;

#endif /* UFIFO_LAYOUT_H */
