# ufifo

[![CI](https://github.com/ShenChen1/ufifo/actions/workflows/ci.yml/badge.svg)](https://github.com/ShenChen1/ufifo/actions/workflows/ci.yml)
[![Release](https://github.com/ShenChen1/ufifo/actions/workflows/release.yml/badge.svg)](https://github.com/ShenChen1/ufifo/actions/workflows/release.yml)

**ufifo** is a lightweight, high-performance shared-memory ring-buffer FIFO library for C and C++. It provides flexible synchronization options and supports both raw byte-stream and structured record modes.

## Why ufifo? (Comparison)

While there are many IPC and message-passing solutions available, **ufifo** is designed specifically to fill the gap for a lightweight, dependency-free shared-memory ring buffer with advanced data distribution patterns. Built with C99 and GCC built-in atomics, it targets GNU/Linux systems.

Here is how `ufifo` compares to other common alternatives:

| Feature | **ufifo** | POSIX Message Queues | Named Pipes (FIFOs) | ZeroMQ (IPC) |
| :--- | :--- | :--- | :--- | :--- |
| **Transport** | **Shared Memory** | Kernel IPC | Kernel VFS | Sockets / Shared Memory |
| **Performance & Latency** | **Extremely High / Low** | Medium | Medium | High / Medium |
| **Data Modes** | **Byte-Stream & Record** | Record only | Byte-Stream only | Record only |
| **Distribution** | **Compete** (`SOLE`) & **Broadcast** (`SHARED`) | Compete only | Compete only | Pub/Sub, Req/Rep, etc. |
| **Event Notification**| **epoll (Bi-directional, io_uring + futex, ET)**| Signals / Threads | `epoll` | Internal / `zmq_poll` |
| **Locking Strategy** | **Configurable** (None, Thread, Process) | Kernel Managed | Kernel Managed | Internal / Complex |

**Key Takeaway:** If you need a hyper-fast, customizable shared-memory ring buffer that can handle both raw byte streams and structured records—and support broadcast to multiple readers across processes—`ufifo` is the perfect fit.

## Key Features

- **Shared-Memory IPC, Zero Kernel Overhead**: Communicate between processes on the same machine at near-memcpy speed. No system calls on the data hot-path — just direct reads and writes to `mmap`'d memory.
- **Two Delivery Models, One API**:
  - `SOLE` — Work queue: each message is consumed by exactly one reader. Scale consumers up or down freely.
  - `SHARED` — Broadcast: every attached reader receives the full stream independently, each at its own pace.
- **Lock-Free SPMC Broadcast**: Pair `LOCK_NONE` with `SHARED` mode for true zero-contention fan-out. One producer, N consumers, no mutex in the data path — ideal for real-time video/sensor/market-data distribution.
- **epoll-Ready, Bi-directional**: Get an `RX` fd (data available) and/or a `TX` fd (space available) to plug directly into your event loop. Backed by modern Linux `io_uring` + `futex` asynchronous event completions — true zero-broker, daemon-free cross-process notifications with Edge-Triggered (ET) semantics.
- **Self-Healing**: Crashed consumers never stall the system. Dead processes are detected automatically, their slots reclaimed, and buffer space recovered — no watchdog, no manual cleanup required.
- **Record Mode with Tag Seeking**: Beyond raw byte streams, push structured records with user-defined boundaries. Tag records and jump directly to the `oldest` or `newest` matching entry, skipping stale data in O(n) scan — perfect for frame-accurate video playback or sensor replay.
- **Custom Serialization Hooks**: Plug in your own `recput`/`recget` callbacks to serialize and deserialize directly inside the ring buffer. The library hands you the raw split-buffer pointers — you control the format, no intermediate copies.
- **Customizable Diagnostics**: Inject your own logging callback via `ufifo_set_log_handler` to integrate `ufifo` warnings and debug outputs seamlessly into your application's logging infrastructure.
- **Safe Across Versions**: A version stamp is embedded into shared memory at creation time. If a client links against an incompatible library version, `ufifo_open` rejects it immediately — no silent corruption.
- **Three Blocking Flavors**: Every read/write operation comes in non-blocking, blocking (`poll()`-based), and timed variants (`_block`, `_timeout`), so you choose the back-pressure strategy that fits your architecture.
- **Lightweight, Minimal Runtime Overhead**: Written in pure C99 + POSIX and statically links `liburing` for kernel-level async futex event multiplexing. No background broker daemons, no socket passing, no complex runtime.

## Common Topologies & Use Cases

`ufifo`'s configuration flexibility allows it to adapt perfectly to wildly different system architectures. Here are the three most mainstream paradigms:

### 1. Lock-Free SPMC Broadcast (The Performance King)
`UFIFO_LOCK_NONE` + `UFIFO_DATA_SHARED` (Single-Producer, Multi-Consumer)

- **Scenario**: High-frequency market data tickers, realtime video frame fan-outs, or IoT sensor telemetry distribution.
- **The Magic**: By combining `LOCK_NONE` with the `SHARED` broadcast mode, each reader is assigned its own independent read pointer. The single producer writes data and updates the write pointer using strict C11 atomic memory barriers (Acquire/Release). Since no two processes try to modify the same variable simultaneously, no locks are needed.
- **The Advantage**: **Actual Zero-Contention.** The single producer broadcasts to N disparate worker processes seamlessly. Consumers fetch data completely lock-free, delivering unparalleled latency benchmarks that crush traditional mutex-bound IPC pipelines.
- **Self-Healing**: If a consumer process crashes, its stale read pointer could block the entire ring buffer. ufifo automatically detects the dead process via OFD lock probing and reaps its slot on the next write attempt — no manual cleanup, no stalled producers.

### 2. Robust MPMC Worker Pool
`UFIFO_LOCK_PROCESS` + `UFIFO_DATA_SOLE` (Multi-Producer, Multi-Consumer)

- **Scenario**: Work-stealing schedulers, API request load balancers, or distributed job processors.
- **The Magic**: Multiple processes safely compete for the exact same payload stream. `SOLE` mode guarantees that any given message is consumed by *exactly one* worker dynamically based on who grabs the lock first.
- **The Advantage**: Highly decoupled scaling with crash tolerance. Thanks to `PTHREAD_MUTEX_ROBUST` under the hood, if a worker process OOMs or segfaults while grabbing a payload from the FIFO, the lock instantly recovers, preventing the entire worker fleet from halting. Dead workers' registration slots are automatically recycled when new workers join.

### 3. epoll-Driven Async Data Mesh
`UFIFO_LOCK_PROCESS` + `UFIFO_OPT_ATTACH` + `ufifo_get_rx_fd()` / `ufifo_get_tx_fd()`

- **Scenario**: Event loops (like `libuv`, epoll-based reactor servers, or real-time trading engines) multiplexing shared-memory IPC streams alongside network sockets.
- **The Magic**: A single event loop thread handles everything through `epoll_wait()`. Rather than requiring an extra background daemon or UNIX domain sockets to pass descriptors via `SCM_RIGHTS`, `ufifo` provides a **brokerless, direct `io_uring` + `futex` architecture**. Each attached process allocates a local `io_uring` ring instance and arms an asynchronous `futex_wait` SQE directly targeting the shared memory futex word. When a producer enqueues data, it performs an atomic futex notify to wake listeners. The kernel completes the operation directly into the process's `io_uring` CQE ring, immediately rendering `ring_fd` readable in `epoll_wait()`.
- **The Advantage**: **Pure Edge-Triggered (ET) semantics with zero data-path overhead.** The hot data path (`ufifo_put` / `ufifo_get`) never takes notification locks and makes zero system calls unless a counterparty is actually waiting. After `epoll_wait()` triggers, simply call `ufifo_drain_rx_fd()` to acknowledge the notification and re-arm, then drain all data in a loop until empty.

## Quick Start

### 1. Byte Stream Mode

```c
#include "ufifo.h"
#include <stdio.h>
#include <string.h>

ufifo_t *fifo = NULL;
ufifo_init_t init = {
    .opt = UFIFO_OPT_ALLOC,
    .alloc = {
        .size = 65536,
        .force = 1,
        .lock = UFIFO_LOCK_PROCESS,
        .data_mode = UFIFO_DATA_SOLE,
        .max_users = 2,
    }
};

if (ufifo_open("demo_fifo", &init, &fifo) == 0) {
    char msg[] = "Hello ufifo!";
    ufifo_put(fifo, msg, strlen(msg) + 1);

    char buf[64];
    ufifo_get(fifo, buf, sizeof(buf));
    printf("Received: %s\n", buf);

    ufifo_destroy(fifo);
}
```

### 2. Record Mode

Record mode enables atomic, structured message delivery. Provide a `recsize` hook so `ufifo` knows boundary sizes. Reads and writes remain strictly aligned to record boundaries, handling ring wrap-around transparently.

```c
static size_t my_recsize(uint8_t *p1, size_t n1, uint8_t *p2) {
    // Return record length encoded in message header
    return *(uint32_t *)p1;
}

ufifo_init_t init = {
    .opt = UFIFO_OPT_ALLOC,
    .alloc = { .size = 65536, .force = 1, .lock = UFIFO_LOCK_PROCESS },
    .hook = { .recsize = my_recsize }
};
```

### 3. epoll Integration (Edge-Triggered)

Multiplex `ufifo` into an `epoll` reactor alongside socket descriptors:

```c
// 1. Get notification file descriptor and register with epoll
int rx_fd = ufifo_get_rx_fd(fifo);
struct epoll_event ev = { .events = EPOLLIN, .data.ptr = fifo };
epoll_ctl(epfd, EPOLL_CTL_ADD, rx_fd, &ev);

// 2. Event loop (Edge-Triggered contract: Drain-then-Loop-Read)
struct epoll_event events[16];
int n = epoll_wait(epfd, events, 16, -1);
for (int i = 0; i < n; i++) {
    ufifo_t *ready = (ufifo_t *)events[i].data.ptr;

    // Step A: Acknowledge notification and re-arm futex listener
    ufifo_drain_rx_fd(ready);

    // Step B: Drain all available data in a loop
    char buf[256];
    while (ufifo_get(ready, buf, sizeof(buf)) > 0) {
        // Process message...
    }
}
```

## Pros and Cons

Based on its architectural design, `ufifo` has several distinctive advantages and design trade-offs:

### Pros

- **Lock-Free Performance (`UFIFO_LOCK_NONE`)**: Peak performance leveraging C11 acquire/release memory barriers (`smp_load_acquire` / `smp_store_release`) for Single-Producer scenarios, completely bypassing kernel space.
- **Brokerless Async Notification (`io_uring` + `futex`)**: Direct in-kernel asynchronous `futex_wait` operations via per-process `io_uring` instances. Eliminates background daemon processes, UNIX domain socket passing, and IPC signaling bottlenecks.
- **Zero Overhead on Hot Data Path**: Pure Edge-Triggered (ET) notification design. Producer and consumer write/read operations directly mutate shared memory without taking notification locks or issuing redundant kernel wakeups.
- **Multi-Layer Crash Recovery**: Combines `PTHREAD_MUTEX_ROBUST` (auto-recovers deadlocked mutexes), OFD lock-based liveness detection (kernel-mediated, zero-overhead dead process detection), and automatic dead-reader reaping (transparently reclaims buffer space and registration slots).
- **Race-Free Lifecycle**: OFD file locking + `init_done` atomic fence eliminates initialization race conditions between `ALLOC` and `ATTACH` without sleep/retry polling.
- **Versatile Distribution Modes**: Natively supports both `SOLE` (competing consumers, ideal for worker pools) and `SHARED` (broadcast/pub-sub topologies).
- **Zero-Allocation Record Hooks**: Custom callbacks (`recsize`, `recput`, `recget`) enable direct serialization/deserialization within the shared ring buffer, avoiding intermediate memory copies.

### Cons

- **Local IPC Only**: Restricted to communication within a single machine via POSIX shared memory (`shm_open` and `mmap`). Cannot span across network boundaries.
- **Fixed Power-of-Two Capacity**: Buffer size is established during initialization and must be a power of two. Dynamic buffer resizing is not supported.
- **Linux Specificity & Modern Kernel Requirement**: Relies on modern Linux kernel capabilities, specifically `io_uring` futex support (`IORING_OP_FUTEX_WAIT`), open file description (OFD) locks (`F_OFD_SETLK`), and robust pthread mutexes. Not portable to non-Linux environments like macOS or Windows.
- **Setup Complexity for Record Hooks**: Utilizing advanced record mode and custom hooks requires writing specific serialization callbacks, requiring slightly more initial setup than raw stream pipes.

## Performance & Benchmarks

`ufifo` maximizes performance by combining shared-memory ring buffers with fine-grained memory barriers and asynchronous kernel notification queues:

- **Lock-Free Operation (`UFIFO_LOCK_NONE`)**: Sub-10ns operations on hot paths without lock contention. Dual ctrl/data lock architecture ensures registration/unregistration never stalls streaming readers/writers.
- **Smart Futex Arming & Coalescing**: Futex wakeups are strictly guarded by `futex_rx_armed` / `futex_tx_armed` atomic flags and `rx_waiters` / `tx_waiters`. Writers and readers skip kernel futex wakeup syscalls unless a counterparty is actively waiting or has armed an epoll trigger, minimizing kernel transitions during high-throughput bursts.

Run the Google Benchmark suite `ufifo_bench` to test throughput and latency metrics directly on your target hardware:

```bash
./build/bin/ufifo_bench
```

## Build Instructions

`ufifo` requires CMake 3.16+ and GCC/Clang on Linux. The build system automatically compiles and statically links the required `liburing` component.

### Building the Project

```bash
# Configure the build directory
cmake -B build

# Build the project
cmake --build build -j$(nproc)
```

To enable Code Coverage or Sanitizers, pass the respective options during configuration:

```bash
# Enable Code Coverage
cmake -B build -DCOVERAGE=ON
cmake --build build --target coverage -j$(nproc)

# Enable Address and Undefined Behavior Sanitizers
cmake -B build-asan -DSANITIZER="asan,ubsan"
cmake --build build-asan -j$(nproc)
ctest --test-dir build-asan --output-on-failure --timeout 300

# Generate Doxygen API Documentation (optional)
cmake --build build --target doc
```

## Running Tests and Examples

The project uses CTest for testing. To run the tests:

```bash
cd build
ctest --output-on-failure
```

The compiled examples can be found in the `build/bin` directory.

## License

This project is licensed under the [MIT License](LICENSE).
