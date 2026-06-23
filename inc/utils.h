#ifndef _UTILS_H_
#define _UTILS_H_

#define ARRAY_SIZE(ary) (sizeof((ary))/sizeof(*(ary)))

#define container_of(ptr, type, member) \
    (type *)((char *)(ptr) - (char *)&((type *)0)->member)

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

#define unlikely(x)                     __builtin_expect(!!(x), 0)
#define likely(x)                       __builtin_expect(!!(x), 1)

#define smp_load_acquire(p)             __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define smp_store_release(p, v)         __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define atomic_fetch_add(p, v)          __atomic_fetch_add((p), (v), __ATOMIC_ACQ_REL)
#define atomic_fetch_sub(p, v)          __atomic_fetch_sub((p), (v), __ATOMIC_ACQ_REL)
#define atomic_xchg(p, v)               __atomic_exchange_n((p), (v), __ATOMIC_ACQ_REL)
#define atomic_cmpxchg(ptr, exp, des)   __atomic_compare_exchange_n((ptr), (exp), (des), 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
#define READ_ONCE(p)                    __atomic_load_n((p), __ATOMIC_RELAXED)
#define WRITE_ONCE(p, v)                __atomic_store_n((p), (v), __ATOMIC_RELAXED)

#endif /* _UTILS_H_ */