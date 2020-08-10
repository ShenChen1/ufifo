#ifndef _UTILS_H_
#define _UTILS_H_

#define ARRAY_SIZE(ary) (sizeof((ary))/sizeof(*(ary)))

#define min(x, y) ({                \
    typeof(x) _min1 = (x);          \
    typeof(y) _min2 = (y);          \
    (void) (&_min1 == &_min2);      \
    _min1 < _min2 ? _min1 : _min2; })

#endif /* _UTILS_H_ */