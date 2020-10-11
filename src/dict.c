#include <stdlib.h>
#include <string.h>
#include "dict.h"

struct dictElt {
    unsigned long hash; /* full hash of key */
    void *key;
    void *value;
    struct dictElt *next;
};

struct dict {
    int tableSize;          /* number of slots in table */
    int numElements;        /* number of elements */
    struct dictElt **table; /* linked list heads */
    /* these save arguments passed at creation */
    dictctops_t keyOps;
    dictctops_t valueOps;
};

#define INITIAL_TABLESIZE (16)
#define TABLESIZE_MULTIPLIER (2)
#define TABLE_GROW_DENSITY (1)

dict_t *dictCreate(dictctops_t *keyOps, dictctops_t *valueOps)
{
    dict_t *d;
    int i;

    d = malloc(sizeof(*d));
    if (d == 0)
        return 0;

    d->tableSize = INITIAL_TABLESIZE;
    d->numElements = 0;
    memcpy(&d->keyOps, keyOps, sizeof(dictctops_t));
    memcpy(&d->valueOps, valueOps, sizeof(dictctops_t));
    d->table = malloc(sizeof(*(d->table)) * d->tableSize);
    if (d->table == 0) {
        free(d);
        return 0;
    }

    for (i = 0; i < d->tableSize; i++) {
        d->table[i] = 0;
    }

    return d;
}

void dictDestroy(dict_t *d)
{
    int i;
    struct dictElt *e;
    struct dictElt *next;

    for (i = 0; i < d->tableSize; i++) {
        for (e = d->table[i]; e != 0; e = next) {
            next = e->next;
            d->keyOps.delete(e->key, d->keyOps.arg);
            d->valueOps.delete(e->value, d->valueOps.arg);
            free(e);
        }
    }
    free(d->table);
    free(d);
}

/* return pointer to element with given key, if any */
static struct dictElt *dictFetch(dict_t *d, const void *key)
{
    unsigned long h;
    int i;
    struct dictElt *e;

    h = d->keyOps.hash(key, d->keyOps.arg);
    i = h % d->tableSize;
    for (e = d->table[i]; e != 0; e = e->next) {
        if (e->hash == h && d->keyOps.equal(key, e->key, d->keyOps.arg)) {
            /* found it */
            return e;
        }
    }
    /* didn't find it */
    return 0;
}

/* increase the size of the dictionary, rehashing all table  elements */
static void dictGrow(dict_t *d)
{
    struct dictElt **old_table;
    int old_size;
    int i;
    struct dictElt *e;
    struct dictElt *next;
    int new_pos;

    /* save old table */
    old_table = d->table;
    old_size = d->tableSize;

    /* make new table */
    d->tableSize *= TABLESIZE_MULTIPLIER;
    d->table = malloc(sizeof(*(d->table)) * d->tableSize);
    if (d->table == 0) {
        /* put the old one back */
        d->table = old_table;
        d->tableSize = old_size;
        return;
    }
    /* else */
    /* clear new table */
    for (i = 0; i < d->tableSize; i++)
        d->table[i] = 0;

    /* move all elements of old table to new table */
    for (i = 0; i < old_size; i++) {
        for (e = old_table[i]; e != 0; e = next) {
            next = e->next;
            /* find the position in the new table */
            new_pos = e->hash % d->tableSize;
            e->next = d->table[new_pos];
            d->table[new_pos] = e;
        }
    }

    /* don't need this any more */
    free(old_table);
}

void dictSet(dict_t *d, const void *key, const void *value)
{
    int tablePosition;
    struct dictElt *e;

    e = dictFetch(d, key);
    if (e != 0) {
        /* change existing setting */
        d->valueOps.delete(e->value, d->valueOps.arg);
        e->value = value ? d->valueOps.copy(value, d->valueOps.arg) : 0;
    }
    else {
        /* create new element */
        e = malloc(sizeof(*e));
        if (e == 0) {
            abort();
        }

        e->hash = d->keyOps.hash(key, d->keyOps.arg);
        e->key = d->keyOps.copy(key, d->keyOps.arg);
        e->value = value ? d->valueOps.copy(value, d->valueOps.arg) : 0;

        /* link it in */
        tablePosition = e->hash & d->tableSize;
        e->next = d->table[tablePosition];
        d->table[tablePosition] = e;

        d->numElements++;

        if (d->numElements > d->tableSize * TABLE_GROW_DENSITY) {
            /* grow and rehash */
            dictGrow(d);
        }
    }
}

const void *dictGet(dict_t *d, const void *key)
{
    struct dictElt *e;

    e = dictFetch(d, key);
    if (e != NULL) {
        return e->value;
    }

    return NULL;
}

/* int functions */
/* We assume that int can be cast to void * and back without damage */
static unsigned long dictIntHash(const void *x, void *arg) { return (size_t)x; }
static int dictIntEqual(const void *x, const void *y, void *arg)
{
    return ((size_t)x) == ((size_t)y);
}
static void *dictIntCopy(const void *x, void *arg) { return (void *)x; }
static void dictIntDelete(void *x, void *arg) { ; }

dictctops_t DictIntOps = {
    dictIntHash,
    dictIntEqual,
    dictIntCopy,
    dictIntDelete,
    NULL};

dictctops_t *dictIntOps(void *arg)
{
    dictctops_t *intOps = &DictIntOps;
    intOps->arg = (void *)arg;
    return intOps;
}

/* common utilities for string and mem */
static unsigned long hashMem(const unsigned char *s, int len)
{
    unsigned long h;
    int i;

    h = 0;
    for (i = 0; i < len; i++) {
        h = (h << 13) + (h >> 7) + h + s[i];
    }
    return h;
}

static void dictDeleteFree(void *x, void *arg) { free(x); }

/* string functions */
static unsigned long dictStringHash(const void *x, void *arg)
{
    return hashMem(x, strlen(x));
}

static int dictStringEqual(const void *x, const void *y, void *arg)
{
    return !strcmp((const char *)x, (const char *)y);
}

static void *dictStringCopy(const void *x, void *arg)
{
    const char *s;
    char *s2;

    s = x;
    s2 = malloc(sizeof(*s2) * (strlen(s) + 1));
    strcpy(s2, s);
    return s2;
}

dictctops_t DictStringOps = {
    dictStringHash,
    dictStringEqual,
    dictStringCopy,
    dictDeleteFree,
    NULL};

dictctops_t *dictStringOps(void *arg)
{
    dictctops_t *stringOps = &DictStringOps;
    stringOps->arg = (void *)arg;
    return stringOps;
}

/* mem functions */
static unsigned long dictMemHash(const void *x, void *arg)
{
    return hashMem(x, (size_t)arg);
}

static int dictMemEqual(const void *x, const void *y, void *arg)
{
    return !memcmp(x, y, (size_t)arg);
}

static void *dictMemCopy(const void *x, void *arg)
{
    void *x2;

    x2 = malloc((size_t)arg);
    memcpy(x2, x, (size_t)arg);
    return x2;
}

dictctops_t DictMemOps = {
    dictMemHash,
    dictMemEqual,
    dictMemCopy,
    dictDeleteFree,
    NULL};

dictctops_t *dictMemOps(size_t len)
{
    dictctops_t *memOps = &DictMemOps;
    memOps->arg = (void *)len;
    return memOps;
}