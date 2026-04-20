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
| **Event Notification**| **epoll (Bi-directional RX/TX)**| Signals / Threads | `epoll` | Internal / `zmq_poll` |
| **Locking Strategy** | **Configurable** (None, Thread, Process) | Kernel Managed | Kernel Managed | Internal / Complex |

**Key Takeaway:** If you need a hyper-fast, customizable shared-memory ring buffer that can handle both raw byte streams and structured records—and support broadcast to multiple readers across processes—`ufifo` is the perfect fit.

## Key Features

- **Shared-Memory IPC, Zero Kernel Overhead**: Communicate between processes on the same machine at near-memcpy speed. No system calls on the data hot-path — just direct reads and writes to `mmap`'d memory.
- **Two Delivery Models, One API**:
  - `SOLE` — Work queue: each message is consumed by exactly one reader. Scale consumers up or down freely.
  - `SHARED` — Broadcast: every attached reader receives the full stream independently, each at its own pace.
- **Lock-Free SPMC Broadcast**: Pair `LOCK_NONE` with `SHARED` mode for true zero-contention fan-out. One producer, N consumers, no mutex in the data path — ideal for real-time video/sensor/market-data distribution.
- **epoll-Ready, Bi-directional**: Get an `RX` fd (data available) and/or a `TX` fd (space available) to plug directly into your event loop. Works with `epoll`, `poll`, or any fd-based reactor — mix ufifo streams with network sockets in a single thread.
- **Self-Healing**: Crashed consumers never stall the system. Dead processes are detected automatically, their slots reclaimed, and buffer space recovered — no watchdog, no manual cleanup required.
- **Record Mode with Tag Seeking**: Beyond raw byte streams, push structured records with user-defined boundaries. Tag records and jump directly to the `oldest` or `newest` matching entry, skipping stale data in O(n) scan — perfect for frame-accurate video playback or sensor replay.
- **Custom Serialization Hooks**: Plug in your own `recput`/`recget` callbacks to serialize and deserialize directly inside the ring buffer. The library hands you the raw split-buffer pointers — you control the format, no intermediate copies.
- **Safe Across Versions**: A version stamp is embedded into shared memory at creation time. If a client links against an incompatible library version, `ufifo_open` rejects it immediately — no silent corruption.
- **Three Blocking Flavors**: Every read/write operation comes in non-blocking, blocking, and timed variants (`_block`, `_timeout`), so you choose the back-pressure strategy that fits your architecture.
- **Lightweight, No External Dependencies**: Pure C99 + POSIX. No Boost, no Protobuf, no ZeroMQ runtime — just link against `librt` and `libpthread`.

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

- **Scenario**: Event loops (like `libuv`, Redis modules, or async game servers) needing to multiplex IPC streams alongside network sockets.
- **The Magic**: A core thread handles everything through `epoll_wait()`. When backend workers enqueue responses into the `ufifo`, a wake-up signal travels through a dedicated Unix Domain Socket (`TX`/`RX` fd) out-of-band to awaken the `epoll` loop. After `epoll_wait` returns, simply call `ufifo_drain_rx_fd()` or `ufifo_drain_tx_fd()` to re-arm the notification state machine.
- **The Advantage**: 100% non-blocking processing. Wait on sockets and local IPC FIFO streams simultaneously in the exact same event loop.

## Quick Start

### Byte Stream Mode

In byte stream mode, `ufifo` acts like a traditional pipe. Data is pushed and pulled seamlessly without any structural constraints.

### Record Mode

Record mode enables atomic message delivery. You define a hook (`recsize`) to tell `ufifo` the byte length of the record. `ufifo` will then ensure reads are always aligned to your record boundaries, even dealing with ring-buffer wraparound automatically.

## Pros and Cons

Based on its architectural design, `ufifo` has several distinctive advantages and some inherent limitations:

### Pros

- **Lock-Free Performance (`UFIFO_LOCK_NONE`)**: Achieves extreme high performance leveraging C11 memory barriers (`smp_load_acquire` / `smp_store_release`) for Single-Producer scenarios, completely bypassing kernel space.
- **Multi-Layer Crash Recovery**: Combines `PTHREAD_MUTEX_ROBUST` (auto-recovers deadlocked mutexes), OFD lock-based liveness detection (kernel-mediated, zero-overhead dead process detection), and automatic dead-reader reaping (transparently reclaims buffer space and registration slots).
- **Race-Free Lifecycle**: OFD file locking + `init_done` atomic fence eliminates initialization race conditions between `ALLOC` and `ATTACH` without resorting to sleep/retry polling.
- **Versatile Distribution Modes**: Natively supports both `SOLE` (competing consumers, perfect for worker pools) and `SHARED` (broadcast/pub-sub topologies).
- **Asynchronous `epoll` Integration**: Employs out-of-band notifications via Unix Domain Sockets (UDS), allowing `ufifo` descriptors to be multiplexed into standard event loops. Internal states (`REGISTERED` / `PENDING`) coalesce notifications to minimize UDS syscall overhead.
- **Zero-Allocation Record Hooks**: Custom callbacks (`recsize`, `recput`, `recget`) enable direct serialization/deserialization within the shared ring buffer, avoiding intermediate memory copies.
- **Lightweight & Dependency-Free**: Relies exclusively on standard C99/POSIX interfaces with no external third-party dependencies.

### Cons

- **Local IPC Only**: Restricted to communication within a single machine. Because it uses POSIX shared memory (`shm_open` and `mmap`), it cannot span across network boundaries.
- **Fixed Power-of-Two Capacity**: The buffer size is established during initialization and must be a power of two. It cannot dynamically allocate more memory or grow to accommodate traffic spikes once initialized.
- **UDS Notification Overhead**: While `epoll` support is highly convenient for async runtimes, transmitting wake-up events over Unix Domain Sockets introduces system-call overhead compared to pure atomic busy-waiting.
- **Platform Specificity**: Designed heavily around Linux-specific semantics (e.g., `F_OFD_SETLK` for liveness detection, abstract namespace UDS for epoll notifications, and robust mutexes). This significantly limits portability to non-Linux environments like macOS or Windows.
- **Setup Complexity**: Utilizing the advanced record mode and custom hooks requires writing specific serialization callbacks, making the initial setup slightly more complex than a basic pipe or POSIX Message Queue.

## Performance & Benchmarks

`ufifo` relies heavily on fine-grained C11 memory barriers (`smp_load_acquire` / `smp_store_release`) to maximize performance. 

- **Lock-Free Operation (`UFIFO_LOCK_NONE`)**: Achieves peak performance, isolating the memory barrier cost without contention. The ctrl/data dual-lock architecture ensures that even administrative operations (register/unregister) never block the hot data path.
- **Multithreaded Load**: Throughput remains highly efficient even under heavy load (MPSC scenarios) thanks to process-shared robust mutexes minimizing wait times.
- **Shared Broadcast**: Data broadcast introduces virtually zero overhead since consumers seamlessly read without mutating producer states. Dead reader reaping runs only on the slow path (when buffer space is exhausted) to avoid polluting the fast path.
- **Notification Coalescing**: The epoll state machine (`IDLE → REGISTERED → PENDING → drain → REGISTERED`) prevents notification storms under burst traffic — multiple puts between drains generate only a single UDS sendto.

You can run the benchmark suite `ufifo_bench` in the `build/bin` directory to test throughput and latency metrics directly on your target hardware.

## Build Instructions

### Building the Project

```bash
# Configure the build directory
cmake -B build

# Build the project
cmake --build build -j$(nproc)
```

To enable Code Coverage or Sanitizers, you can pass the respective options during the configuration step:

```bash
# Enable Code Coverage
cmake -B build -DCOVERAGE=ON

# Enable Address and Undefined Behavior Sanitizers
cmake -B build -DSANITIZER="asan,ubsan"
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
