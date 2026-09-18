/**
 * @file ufifo.h
 * @brief Shared-memory ring-buffer FIFO with byte-stream and record modes.
 */

#ifndef _UFIFO_H_
#define _UFIFO_H_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UFIFO_API
#if defined __GNUC__ && __GNUC__ >= 4
#define UFIFO_API __attribute__((visibility("default")))
#else
#define UFIFO_API
#endif
#endif

/** @brief Maximum FIFO name length in bytes, excluding the null terminator. */
#define UFIFO_NAME_MAX (64U)

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
typedef size_t (*ufifo_recsize_hook_t)(uint8_t *p1, size_t n1, uint8_t *p2);
typedef size_t (*ufifo_rectag_hook_t)(uint8_t *p1, size_t n1, uint8_t *p2);
typedef size_t (*ufifo_recput_hook_t)(uint8_t *p1, size_t n1, uint8_t *p2, void *arg);
typedef size_t (*ufifo_recget_hook_t)(uint8_t *p1, size_t n1, uint8_t *p2, void *arg);
/** @} */

/** @brief Structured version information. */
typedef struct {
    uint32_t major;   /**< Major version (ABI-breaking changes). */
    uint32_t minor;   /**< Minor version (backwards-compatible features). */
    uint32_t patch;   /**< Patch version (bug fixes). */
    char version[32]; /**< Full version string (git tag or commit hash). */
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
    size_t size;                 /**< Buffer size in bytes (rounded up to 2^n). */
    int32_t force;               /**< 1 = recreate if no active handles; 0 = reuse. */
    ufifo_lock_e lock;           /**< Locking strategy. */
    ufifo_data_mode_e data_mode; /**< Data distribution mode. */
    size_t max_users;            /**< Max concurrent consumers; determines shared user-slot capacity. */
    uint32_t reserved[11];       /**< Reserved for ABI compatibility. */
} ufifo_alloc_t;

/** @brief ATTACH-mode configuration (reserved). */
typedef struct {
    uint32_t reserved[8];
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
 * @param name   Shared-memory name (must be unique and no longer than UFIFO_NAME_MAX bytes).
 * @param init   Initialization parameters (mode, hooks, alloc config).
 * @param handle [out] Receives the created FIFO handle on success.
 * @return 0 on success, negative errno on failure.
 * @retval -ENOENT ATTACH found no object at the requested name.
 * @retval -EAGAIN ATTACH observed an object being initialized or replaced; the caller may retry.
 */
UFIFO_API int ufifo_open(const char *name, const ufifo_init_t *init, ufifo_t **handle);

/**
 * @brief Close handle (detach only, shared memory persists).
 * @param handle FIFO handle to close.
 * @return 0 on success.
 */
UFIFO_API int ufifo_close(ufifo_t *handle);

/**
 * @brief Destroy handle and unlink the underlying shared memory.
 * @param handle FIFO handle to destroy.
 * @return 0 on success, -EBUSY while another opened handle is active.
 */
UFIFO_API int ufifo_destroy(ufifo_t *handle);

/**
 * @brief Get total buffer capacity.
 * @param handle FIFO handle.
 * @return Buffer size in bytes.
 */
UFIFO_API size_t ufifo_size(ufifo_t *handle);

/**
 * @brief Reset all read/write pointers to zero (clear data).
 * @param handle FIFO handle.
 */
UFIFO_API void ufifo_reset(ufifo_t *handle);

/**
 * @brief Get bytes of data currently stored.
 * @param handle FIFO handle.
 * @return Number of bytes used.
 */
UFIFO_API size_t ufifo_len(ufifo_t *handle);

/**
 * @brief Discard the next record (record mode) or data (byte-stream).
 * @param handle FIFO handle.
 */
UFIFO_API void ufifo_skip(ufifo_t *handle);

/**
 * @brief Get byte-length of the next record.
 * @param handle FIFO handle.
 * @return Record size in bytes, 0 if FIFO is empty.
 */
UFIFO_API size_t ufifo_peek_len(ufifo_t *handle);

/**
 * @brief Non-blocking write.
 * @param handle FIFO handle.
 * @param buf    Data to write.
 * @param size   Number of bytes to write.
 * @return Non-negative bytes written (0 is valid for a zero-length write), or a negative errno on failure.  On
 * failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_put(ufifo_t *handle, void *buf, size_t size);

/**
 * @brief Blocking write — waits indefinitely for space.
 * @param handle FIFO handle.
 * @param buf    Data to write.
 * @param size   Number of bytes to write.
 * @return Non-negative bytes written (0 is valid for a zero-length write), or a negative errno on failure.  On
 * failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_put_block(ufifo_t *handle, void *buf, size_t size);

/**
 * @brief Timed write.
 * @param handle   FIFO handle.
 * @param buf      Data to write.
 * @param size     Number of bytes to write.
 * @param millisec Timeout in milliseconds.
 * @return Non-negative bytes written (0 is valid for a zero-length write), or a negative errno on failure/timeout.  On
 * failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_put_timeout(ufifo_t *handle, void *buf, size_t size, long millisec);

/**
 * @brief Non-blocking read.
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Non-negative bytes read (0 is valid when no bytes are transferred), or a negative errno on failure.  On
 * failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_get(ufifo_t *handle, void *buf, size_t size);

/**
 * @brief Blocking read — waits indefinitely for data.
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Non-negative bytes read (0 is valid when no bytes are transferred), or a negative errno on failure.  On
 * failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_get_block(ufifo_t *handle, void *buf, size_t size);

/**
 * @brief Timed read.
 * @param handle   FIFO handle.
 * @param buf      Buffer to receive data.
 * @param size     Buffer capacity in bytes.
 * @param millisec Timeout in milliseconds.
 * @return Non-negative bytes read (0 is valid when no bytes are transferred), or a negative errno on failure/timeout.
 * On failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_get_timeout(ufifo_t *handle, void *buf, size_t size, long millisec);

/**
 * @brief Non-blocking peek (read without consuming).
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Non-negative bytes peeked (0 is valid when no bytes are transferred), or a negative errno on failure.  On
 * failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_peek(ufifo_t *handle, void *buf, size_t size);

/**
 * @brief Blocking peek — waits indefinitely for data.
 * @param handle FIFO handle.
 * @param buf    Buffer to receive data.
 * @param size   Buffer capacity in bytes.
 * @return Non-negative bytes peeked (0 is valid when no bytes are transferred), or a negative errno on failure.  On
 * failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_peek_block(ufifo_t *handle, void *buf, size_t size);

/**
 * @brief Timed peek (read without consuming).
 * @param handle   FIFO handle.
 * @param buf      Buffer to receive data.
 * @param size     Buffer capacity in bytes.
 * @param millisec Timeout in milliseconds.
 * @return Non-negative bytes peeked (0 is valid when no bytes are transferred), or a negative errno on failure/timeout.
 * On failure, errno is also set to the corresponding positive error number.
 */
UFIFO_API ssize_t ufifo_peek_timeout(ufifo_t *handle, void *buf, size_t size, long millisec);

/**
 * @brief Seek to oldest record matching @p tag.
 * @param handle FIFO handle.
 * @param tag    Tag value to search for.
 * @return 0 on success, -ESPIPE if tag not found (FIFO drained).
 */
UFIFO_API int ufifo_oldest(ufifo_t *handle, uint32_t tag);

/**
 * @brief Seek to newest record matching @p tag, discarding older ones.
 * @param handle FIFO handle.
 * @param tag    Tag value to search for.
 * @return 0 on success, -ESPIPE if tag not found (FIFO drained).
 */
UFIFO_API int ufifo_newest(ufifo_t *handle, uint32_t tag);

/**
 * @brief User-defined log callback.
 * @param arg User-provided context.
 * @param fmt Format string.
 * @param ap  Argument list.
 */
typedef void (*ufifo_log_cb)(void *arg, const char *fmt, va_list ap);

/**
 * @brief Set global log handler for the library.
 * @param cb  Log callback function.
 * @param arg User context passed to the callback.
 */
UFIFO_API void ufifo_set_log_handler(ufifo_log_cb cb, void *arg);

/**
 * @brief Dump the internal status of the FIFO for debugging.
 * @param handle FIFO handle.
 */
UFIFO_API void ufifo_dump(ufifo_t *handle);

/**
 * @brief Get the currently linked library's version string.
 * @return Null-terminated version string (e.g. "v1.2.3" or git hash).
 */
UFIFO_API const char *ufifo_get_version(void);

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
UFIFO_API int ufifo_get_version_info(ufifo_t *handle, ufifo_version_t *ver);

#ifdef __cplusplus
}
#endif

#endif /* _UFIFO_H_ */
