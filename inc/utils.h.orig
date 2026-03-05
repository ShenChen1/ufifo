#ifndef _UTILS_H_
#define _UTILS_H_

#define ARRAY_SIZE(ary) (sizeof((ary))/sizeof(*(ary)))

#define container_of(ptr, type, member) \
    (type *)((char *)(ptr) - (char *) &((type *)0)->member)

#define min(x, y) ({                \
    typeof(x) _min1 = (x);          \
    typeof(y) _min2 = (y);          \
    (void) (&_min1 == &_min2);      \
    _min1 < _min2 ? _min1 : _min2; })

#define smp_wmb __sync_synchronize

#endif /* _UTILS_H_ */