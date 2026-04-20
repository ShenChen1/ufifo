#ifndef UFIFO_INTERNAL_H
#define UFIFO_INTERNAL_H

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "kfifo.h"
#include "log2.h"
#include "ufifo.h"
#include "utils.h"

#define UFIFO_MAGIC (0xf1f0f1f0)
#define UFIFO_CHECK_HANDLE_FUNC(handle) \
    assert((handle));                   \
    assert((handle)->magic == UFIFO_MAGIC);

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

struct ufifo {
    unsigned int magic;

    char name[NAME_MAX];
    unsigned int user_id;

    ufifo_hook_t hook;
    kfifo_t kfifo;
    sem_t *bsem_wr;
    sem_t *bsem_rd;

    int shm_fd;
    unsigned int shm_size;
    void *shm_mem;

    int ctrl_fd;
    size_t ctrl_size;
    ufifo_ctrl_t *ctrl;

    int rx_efd;
    int tx_efd;
};

/* ufifo_sync.c */
int __ufifo_ctrl_lock(ufifo_t *ufifo);
int __ufifo_ctrl_unlock(ufifo_t *ufifo);
int __ufifo_data_lock(ufifo_t *ufifo);
int __ufifo_data_unlock(ufifo_t *ufifo);
int __ufifo_ofd_lock(int fd, unsigned int user_id);
int __ufifo_ofd_unlock(int fd, unsigned int user_id);
int __ufifo_is_user_dead(int fd, unsigned int user_id);
int __ufifo_init_lock(int fd);
int __ufifo_init_wait(int fd);
int __ufifo_init_unlock(int fd);
int __ufifo_lock_init(ufifo_t *ufifo, ufifo_lock_e type);
int __ufifo_lock_deinit(ufifo_t *ufifo);
int __ufifo_bsem_init(sem_t *bsem, unsigned int value);
int __ufifo_bsem_deinit(sem_t *bsem);
int __ufifo_bsem_wait(sem_t *bsem, ufifo_t *ufifo);
int __ufifo_bsem_timedwait(sem_t *bsem, ufifo_t *ufifo, long millisec);
int __ufifo_bsem_post(sem_t *bsem);

/* ufifo_epoll.c */
void __ufifo_efd_notify_rx(ufifo_t *handle);
void __ufifo_efd_notify_tx(ufifo_t *handle);

/* ufifo_init.c */
void __ufifo_reap_dead_user(ufifo_ctrl_t *ctrl, unsigned int user_id);
int __ufifo_is_shared(ufifo_t *ufifo);

#endif /* UFIFO_INTERNAL_H */
