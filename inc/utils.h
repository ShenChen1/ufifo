#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ARRAY_SIZE(ary) (sizeof((ary)) / sizeof(*(ary)))

#define container_of(ptr, type, member) (type *)((char *)(ptr) - (char *)&((type *)0)->member)

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        (void)(&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; \
    })

#define max(x, y)                      \
    ({                                 \
        typeof(x) _max1 = (x);         \
        typeof(y) _max2 = (y);         \
        (void)(&_max1 == &_max2);      \
        _max1 > _max2 ? _max1 : _max2; \
    })

#define range(val, lo, hi) min(max(val, lo), hi)

#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)

typedef bool ufifo_atomic_bool_t;
typedef size_t ufifo_atomic_size_t;
typedef uint32_t ufifo_atomic_uint32_t;

#define ufifo_atomic_load_relaxed(p) __atomic_load_n((p), __ATOMIC_RELAXED)
#define ufifo_atomic_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define ufifo_atomic_load_seq_cst(p) __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define ufifo_atomic_store_relaxed(p, v) __atomic_store_n((p), (v), __ATOMIC_RELAXED)
#define ufifo_atomic_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define ufifo_atomic_fetch_or_seq_cst(p, v) __atomic_fetch_or((p), (v), __ATOMIC_SEQ_CST)
#define ufifo_atomic_compare_exchange_acq_rel(ptr, exp, des) \
    __atomic_compare_exchange_n((ptr), (exp), (des), 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
#define ufifo_atomic_thread_fence_seq_cst() __atomic_thread_fence(__ATOMIC_SEQ_CST)

#endif /* _UTILS_H_ */
