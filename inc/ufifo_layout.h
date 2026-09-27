#ifndef UFIFO_LAYOUT_H
#define UFIFO_LAYOUT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "ufifo.h"
#include "utils.h"

#define UFIFO_LAYOUT_ABI 4U
#define UFIFO_CACHELINE_SIZE 64U

/* Keep independently published RX/TX epochs on separate cache lines. */
typedef struct __attribute__((aligned(UFIFO_CACHELINE_SIZE))) {
    ufifo_atomic_uint32_t value;
    uint8_t reserved[UFIFO_CACHELINE_SIZE - sizeof(ufifo_atomic_uint32_t)];
} ufifo_wait_word_t;

/*
 * Receive-slot control data (stored in shared memory).
 * users[0..max_users-1] are registered user slots.
 * In SOLE mode, users[max_users] stores the global receive position.
 */
typedef struct {
    pid_t pid;
    ufifo_atomic_bool_t active;
    ufifo_atomic_size_t out;
} ufifo_sub_ctrl_t;

/* Global FIFO control data (stored in shared memory) */
typedef struct {
    uint32_t layout_abi;
    ufifo_version_t ver;

    size_t mapping_size;
    size_t data_offset;
    size_t data_size;

    ufifo_atomic_size_t in;
    size_t mask;
    ufifo_atomic_size_t cached_min_out; /* O(1) cache for SHARED mode */

    ufifo_lock_e lock;
    pthread_mutex_t ctrl_mutex; /* always active: protects control data */
    pthread_mutex_t data_mutex; /* governed by ufifo_lock_e: protects index movement */

    ufifo_wait_word_t rx_wait; /* even = idle epoch, odd = armed epoch */
    ufifo_wait_word_t tx_wait; /* even = idle epoch, odd = armed epoch */

    ufifo_data_mode_e data_mode;
    size_t max_users;
    size_t num_users;
    ufifo_sub_ctrl_t users[];
} ufifo_ctrl_t;

#endif /* UFIFO_LAYOUT_H */
