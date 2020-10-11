#ifndef _DICT_H_
#define _DICT_H_

typedef struct dict dict_t;

/* Provides operations for working with keys or values */
typedef struct {
    /* hash function */
    unsigned long (*hash)(const void *datum, void *arg);

    /* returns nonzero if *datum1 == *datum2 */
    int (*equal)(const void *datum1, const void *datum2, void *arg);

    /* make a copy of datum that will survive changes to original */
    void *(*copy)(const void *datum, void *arg);

    /* free a copy */
    void (*delete)(void *datum, void *arg);

    /* extra argument, to allow further specialization */
    void *arg;
} dictctops_t;

/* create a new dictionary with given key and value operations */
/* Note: valueOps.hash and valueOps.equal are not used. */
dict_t *dictCreate(dictctops_t *keyOps, dictctops_t *valueOps);

/* free a dictionary and all the space it contains */
/* This will cal the appropriate delete function for all keys and */
/* values. */
void dictDestroy(dict_t *d);

/* Set dict[key] = value. */
/* Both key and value are copied internally. */
/* If data is the null pointer, remove dict[key]. */
void dictSet(dict_t *d, const void *key, const void *value);

/* Return dict[key], or null if dict[key] has not been set. */
const void *dictGet(dict_t *d, const void *key);

/* Some predefined dictContentsOperations structures */

/*
 * DictIntOps supports int's that have been cast to (void *), e.g.:
 *     d = dictCreate(dictIntOps(NULL), dictIntOps(NULL));
 *     dictSet(d, (void *) 1, (void * 2));
 *     x = (int) dictGet(d, (void * 1));
 */
dictctops_t *dictIntOps(void *arg);

/*
 * Supports null-terminated strings, e.g.:
 *    d = dictCreate(dictStringOps(NULL), dictStringOps(NULL));
 *    dictSet(d, "foo", "bar");
 *    s = dictGet(d, "foo");
 * Note: no casts are needed since C automatically converts
 * between (void *) and other pointer types.
 */
dictctops_t *dictStringOps(void *arg);

/*
 * Supports fixed-size blocks of memory, e.g.:
 *     int x = 1;
 *     int y = 2;
 *     d = dictCreate(DictMemOps(sizeof(int)), dictMemOps(sizeof(int));
 *     dictSet(d, &x, &y);
 *     printf("%d", *dictGet(d, &x);
 */
dictctops_t *dictMemOps(size_t size);

#endif /* _DICT_H_ */