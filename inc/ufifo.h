/**
 * @file ufifo.h
 * @brief Shared-memory ring-buffer FIFO with byte-stream and record modes.
 */

#ifndef _UFIFO_H_
#define _UFIFO_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Hook callbacks for record-oriented mode.
 *
 * All hooks receive data in a split-buffer form due to ring wrap-around:
 *   @c p1[0..n1-1] is the first contiguous segment,
 *   @c p2 is the second segment (from buffer start, length = total - n1).
 * If the record doesn't wrap, n1 >= record size and p2 is unused.
 * @c arg (put/get hooks) is the user buffer passed to ufifo_put / ufifo_get.
 * @{
 */
typedef unsigned int (*ufifo_recsize_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2);
typedef unsigned int (*ufifo_rectag_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2);
typedef unsigned int (*ufifo_recput_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2, void *arg);
typedef unsigned int (*ufifo_recget_hook_t)(unsigned char *p1, unsigned int n1, unsigned char *p2, void *arg);
/** @} */

/** @brief Structured version information. */
typedef struct {
    unsigned int major; /**< Major version (ABI-breaking changes). */
    unsigned int minor; /**< Minor version (backwards-compatible features). */
    unsigned int patch; /**< Patch version (bug fixes). */
    char version[32];   /**< Full version string (git tag or commit hash). */
} ufifo_version_t;

/** @brief FIFO open mode. */
typedef enum {
    UFIFO_OPT_ALLOC,  /**< Create new shared-memory FIFO (owner). */
    UFIFO_OPT_ATTACH, /**< Attach to an existing FIFO (client). */
    UFIFO_OPT_MAX,
} ufifo_opt_e;

/** @brief Mutual-exclusion strategy. */
typedef enum {
    UFIFO_LOCK_NONE,    /**< No locking, single-thread only. */
    UFIFO_LOCK_THREAD,  /**< Intra-process pthread mutex. */
    UFIFO_LOCK_PROCESS, /**< Inter-process robust shared mutex. */
    UFIFO_LOCK_MAX,
} ufifo_lock_e;

/** @brief Consumer data distribution mode. */
typedef enum {
    UFIFO_DATA_SOLE,   /**< Consumers compete for data (only one gets each item). */
    UFIFO_DATA_SHARED, /**< Broadcast — every consumer receives all data. */
    UFIFO_DATA_MAX,
} ufifo_data_mode_e;

/** @brief ALLOC-mode configuration. */
typedef struct {
    unsigned int size;           /**< Buffer size in bytes (rounded up to 2^n). */
    unsigned int force;          /**< 1 = recreate if exists; 0 = reuse. */
    ufifo_lock_e lock;           /**< Locking strategy. */
    ufifo_data_mode_e data_mode; /**< Data distribution mode. */
    unsigned int max_users;      /**< Max concurrent consumers (>= 1). */
    unsigned int reserved[11];   /**< Reserved for ABI compatibility. */
} ufifo_alloc_t;

/** @brief ATTACH-mode configuration (reserved). */
typedef struct {
    unsigned int reserved[8];
} ufifo_attach_t;

/** @brief Record-handling hooks. Set all to NULL for byte-stream mode. */
typedef struct {
    ufifo_recsize_hook_t recsize; /**< Return record byte-length. */
    ufifo_rectag_hook_t rectag;   /**< Return record tag value. */
    ufifo_recput_hook_t recput;   /**< Custom write serializer. */
    ufifo_recget_hook_t recget;   /**< Custom read deserializer. */
} ufifo_hook_t;

/** @brief Initialization parameters for ufifo_open(). */
typedef struct {
    ufifo_opt_e opt; /**< ALLOC or ATTACH. */
    union {
        ufifo_alloc_t alloc;   /**< Valid when opt == ALLOC. */
        ufifo_attach_t attach; /**< Valid when opt == ATTACH. */
    };
    ufifo_hook_t hook; /**< Record hooks (optional). */
} ufifo_init_t;

/** @brief Opaque FIFO handle. */
typedef struct ufifo ufifo_t;

/**
 * @brief Open or create a FIFO.
 * @param name   Shared-memory name (must be unique per FIFO instance).
 * @param init   Initialization parameters (mode, hooks, alloc config).
 * @param handle [out] Receives the created FIFO handle on success.
 * @return 0 on success, negative errno on failure.
 */
int ufifo_open(const char *name, const ufifo_init_t *init, ufifo_t **handle);

/**
 * @brief Close handle (detach only, shared memory persists).
 * @param handle FIFO handle to close.
 * @return 0 on success.
 */
int ufifo_close(ufifo_t *handle);

/**
 * @brief Destroy handle and unlink the underlying shared memory.
 * @param handle FIFO handle to destroy.
 * @return 0 on success.
 */
int ufifo_destroy(ufifo_t *handle);

/**
 * @brief Get total buffer capacity.
 * @param handle FIFO handle.
 * @return Buffer size in bytes.
 */
unsigned int ufifo_size(ufifo_t *handle);

/**
 * @brief Reset all read/write pointers to zero (clear data).
 * @param handle FIFO handle.
 */
void ufifo_reset(ufifo_t *handle);

/**
 * @brief Get bytes of data currently stored.
 * @param handle FIFO handle.
 * @return Number of bytes used.
 */
unsigned int ufifo_len(ufifo_t *handle);

/**
 * @brief Discard the next record (record mode) or data (byte-stream).
 * @param handle FIFO handle.
 */
void ufifo_skip(ufifo_t *handle);

/**
 * @brief Get byte-length of the next record.
 * @param handle FIFO handle.
 * @return Record size in bytes, 0 if FIFO is empty.
 */
unsigned int ufifo_peek_len(ufifo_t *handle);

/**
 * @brief Non-blocking write.
 * @param handle FIFO handle.
 * @param buf    Data to write.
 * @param size   Number of bytes to write.
 * @return Bytes written, 0 if FIFO is full.
 */
unsigned int ufifo_put(ufifo_t *handle, void *buf, unsigned int size);

/**
 * @brief Blocking write — waits indefinitely for space.
 * @param handle FIFO handle.
 * @param buf    Data to write.
 * @param size   Number of bytes to write.
 * @return Bytes written.
 */
unsigned int ufifo_put_block(ufifo_t *handle, void *buf, unsigned int size);

/**
 * @brief Timed write.
 * @param handle   FIFO handle.
 * @param buf      Data to write.
 * @param size     Number of bytes to write.
 * @param millisec Timeout in milliseconds.
 * @return Bytes written, 0 on timeout.
 */
unsigned int ufifo_put_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec);

/**
 * @brief Non-blocking read.
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Bytes read, 0 if FIFO is empty.
 */
unsigned int ufifo_get(ufifo_t *handle, void *buf, unsigned int size);

/**
 * @brief Blocking read — waits indefinitely for data.
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Bytes read.
 */
unsigned int ufifo_get_block(ufifo_t *handle, void *buf, unsigned int size);

/**
 * @brief Timed read.
 * @param handle   FIFO handle.
 * @param buf      Buffer to receive data.
 * @param size     Buffer capacity in bytes.
 * @param millisec Timeout in milliseconds.
 * @return Bytes read, 0 on timeout.
 */
unsigned int ufifo_get_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec);

/**
 * @brief Non-blocking peek (read without consuming).
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Bytes read, 0 if FIFO is empty.
 */
unsigned int ufifo_peek(ufifo_t *handle, void *buf, unsigned int size);

/**
 * @brief Blocking peek — waits indefinitely for data.
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Bytes read.
 */
unsigned int ufifo_peek_block(ufifo_t *handle, void *buf, unsigned int size);

/**
 * @brief Timed peek (read without consuming).
 * @param handle   FIFO handle.
 * @param buf      Buffer to receive data.
 * @param size     Buffer capacity in bytes.
 * @param millisec Timeout in milliseconds.
 * @return Bytes read, 0 on timeout.
 */
unsigned int ufifo_peek_timeout(ufifo_t *handle, void *buf, unsigned int size, long millisec);

/**
 * @brief Seek to oldest record matching @p tag.
 * @param handle FIFO handle.
 * @param tag    Tag value to search for.
 * @return 0 on success, -ESPIPE if tag not found (FIFO drained).
 */
int ufifo_oldest(ufifo_t *handle, unsigned int tag);

/**
 * @brief Seek to newest record matching @p tag, discarding older ones.
 * @param handle FIFO handle.
 * @param tag    Tag value to search for.
 * @return 0 on success, -ESPIPE if tag not found (FIFO drained).
 */
int ufifo_newest(ufifo_t *handle, unsigned int tag);

/**
 * @brief Get fd for epoll multiplexing (cross-process safe).
 *
 * Returns a socket fd that becomes readable when FIFO state changes
 * (data written or consumed). Add this fd to epoll to multiplex
 * multiple FIFOs in a single thread.
 *
 * After epoll_wait returns, call ufifo_drain_rx_fd() / ufifo_drain_tx_fd() to clear,
 * (may return 0 on spurious wake).
 *
 * @param handle FIFO handle.
 * @return fd (>= 0) on success, -1 on failure.
 */
int ufifo_get_rx_fd(ufifo_t *handle);
int ufifo_get_tx_fd(ufifo_t *handle);

/**
 * @brief Drain pending RX/TX notifications from the epoll file descriptor.
 *
 * Clears the underlying socket buffer so that `epoll_wait` doesn't
 * return immediately on subsequent calls in level-triggered mode.
 * Also transitions the internal notification state from PENDING back
 * to REGISTERED, re-arming for the next notification.
 *
 * Should be called after `epoll_wait` returns and before consuming data.
 *
 * @param handle FIFO handle.
 * @return 0 on success, -EINVAL if no epoll fd has been registered.
 */
int ufifo_drain_rx_fd(ufifo_t *handle);
int ufifo_drain_tx_fd(ufifo_t *handle);

/**
 * @brief Dump the internal status of the FIFO for debugging.
 * @param handle FIFO handle.
 */
void ufifo_dump(ufifo_t *handle);

/**
 * @brief Get the currently linked library's version string.
 * @return Null-terminated version string (e.g. "v1.2.3" or git hash).
 */
const char *ufifo_get_version(void);

/**
 * @brief Get structured version information.
 *
 * When @p handle is NULL, returns the compile-time version of the linked
 * library itself. When @p handle is non-NULL, returns the version that was
 * stamped into shared memory when the FIFO was created — useful for
 * diagnosing cross-process version mismatches.
 *
 * @param handle FIFO handle, or NULL to query the library version.
 * @param ver    [out] Receives the version info.
 * @return 0 on success, -EINVAL if @p ver is NULL.
 */
int ufifo_get_version_info(ufifo_t *handle, ufifo_version_t *ver);

#ifdef __cplusplus
}
#endif

#endif /* _UFIFO_H_ */
