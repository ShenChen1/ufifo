#ifndef _UFIFO_H_
#define _UFIFO_H_

typedef unsigned int (*ufifo_recsize_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2);
typedef unsigned int (*ufifo_rectag_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2);
typedef unsigned int (*ufifo_recput_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2, void *arg);
typedef unsigned int (*ufifo_recget_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2, void *arg);

typedef enum {
    UFIFO_OPT_ALLOC,
    UFIFO_OPT_ATTACH,
    UFIFO_OPT_MAX,
} ufifo_opt_e;

typedef struct {
    unsigned int size;
} ufifo_alloc_t;

typedef struct {
    unsigned int shared;
} ufifo_attach_t;

typedef struct {
    ufifo_recsize_hook_t    recsize;
    ufifo_rectag_hook_t     rectag;
    ufifo_recput_hook_t     recput;
    ufifo_recget_hook_t     recget;
} ufifo_hook_t;

typedef enum {
    UFIFO_LOCK_NONE,
    UFIFO_LOCK_MUTEX,
    UFIFO_LOCK_FDLOCK,
    UFIFO_LOCK_MAX,
} ufifo_lock_e;

typedef struct {
    ufifo_lock_e lock;
    ufifo_opt_e opt;
    union {
        ufifo_alloc_t alloc;
        ufifo_attach_t attach;
    };
    ufifo_hook_t hook;
} ufifo_init_t;

typedef struct ufifo ufifo_t;

int ufifo_open(char *name, ufifo_init_t *init, ufifo_t **handle);
int ufifo_close(ufifo_t *handle);
int ufifo_destroy(ufifo_t *handle);
unsigned int ufifo_size(ufifo_t *handle);
void ufifo_reset(ufifo_t *handle);
unsigned int ufifo_len(ufifo_t *handle);
void ufifo_skip(ufifo_t *handle);
unsigned int ufifo_peek_len(ufifo_t *handle);
unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_put_block(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_put_timeout(ufifo_t *handle, void *buf, unsigned long timeout);
unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_get_block(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_get_timeout(ufifo_t *handle, void *buf, unsigned long timeout);
unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_peek_block(ufifo_t *handle, void *buf, unsigned int size);
unsigned int ufifo_peek_timeout(ufifo_t *handle, void *buf, unsigned long timeout);
int ufifo_oldest(ufifo_t *handle, unsigned int tag);
int ufifo_newest(ufifo_t *handle, unsigned int tag);

#endif /* _UFIFO_H_ */