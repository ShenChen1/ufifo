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
| **Blocking Waits**| **Shared futex wait words**| Kernel managed | `poll` / `epoll` | Internal / `zmq_poll` |
| **Locking Strategy** | **Configurable** (None, Thread, Process) | Kernel Managed | Kernel Managed | Internal / Complex |

**Key Takeaway:** If you need a hyper-fast, customizable shared-memory ring buffer that can handle both raw byte streams and structured records—and support broadcast to multiple readers across processes—`ufifo` is the perfect fit.

## Key Features

- **Shared-Memory IPC, Zero Kernel Overhead**: Communicate between processes on the same machine at near-memcpy speed. No system calls on the data hot-path — just direct reads and writes to `mmap`'d memory.
- **Two Delivery Models, One API**:
  - `SOLE` — Work queue: each message is consumed by exactly one reader. Scale consumers up or down freely.
  - `SHARED` — Broadcast: every attached reader receives the full stream independently, each at its own pace.
- **Lock-Free SPMC Broadcast**: Pair `LOCK_NONE` with `SHARED` mode for true zero-contention fan-out. One producer, N consumers, no mutex in the data path — ideal for real-time video/sensor/market-data distribution.
- **Futex-Based Backpressure**: Blocking readers and writers sleep directly on shared 32-bit wait words. The uncontended data path performs no notification syscall, and a publish wakes all waiters for the affected direction.
- **Explicit Crash Recovery**: Dead consumers are reaped automatically. If a process dies while holding the robust data mutex, the next locker discards the uncertain ring contents, returns `-EOWNERDEAD`, and restores service for later operations.
- **Record Mode with Tag Seeking**: Beyond raw byte streams, push structured records with user-defined boundaries. Tag records and jump directly to the `oldest` or `newest` matching entry, skipping stale data in O(n) scan — perfect for frame-accurate video playback or sensor replay.
- **Custom Serialization Hooks**: Plug in your own `recput`/`recget` callbacks to serialize and deserialize directly inside the ring buffer. The library hands you the raw split-buffer pointers — you control the format, no intermediate copies.
- **Customizable Diagnostics**: Inject your own logging callback via `ufifo_set_log_handler` to integrate `ufifo` warnings and debug outputs seamlessly into your application's logging infrastructure.
- **Safe Across Versions**: A version stamp is embedded into shared memory at creation time. If a client links against an incompatible library version, `ufifo_open` rejects it immediately — no silent corruption.
- **Three Blocking Flavors**: Every read/write operation comes in non-blocking, blocking (futex-based), and timed variants (`_block`, `_timeout`), so you choose the back-pressure strategy that fits your architecture.
- **Unambiguous Results**: Data and length APIs return the actual byte count when `ret >= 0`; handle control APIs return `0` on success. These handle APIs return the corresponding negative `errno` on failure and also set `errno`.
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
- **The Advantage**: Highly decoupled scaling with explicit crash detection. `PTHREAD_MUTEX_ROBUST` prevents permanent mutex deadlock; the recovering operation reports `-EOWNERDEAD` instead of consuming uncertain payloads. Dead workers' registration slots are automatically recycled.

### 3. Bounded Blocking Pipeline
`UFIFO_LOCK_PROCESS` + `ufifo_put_block()` / `ufifo_get_block()`

- **Scenario**: Process pipelines that need strict backpressure without polling loops or helper processes.
- **The Magic**: Readers arm a receive wait word only while the FIFO is empty; writers arm a transmit wait word only while capacity is insufficient. Every waiter rechecks the predicate after arming, which closes the lost-wakeup window.
- **The Advantage**: Idle workers consume no CPU, while the no-waiter hot path avoids notification syscalls and extra cache-line writes.

## Quick Start

### Byte Stream Mode

In byte stream mode, `ufifo` acts like a traditional pipe. Data is pushed and pulled seamlessly without any structural constraints.

### Record Mode

Record mode enables atomic message delivery. You define a hook (`recsize`) to tell `ufifo` the byte length of the record. `ufifo` will then ensure reads are always aligned to your record boundaries, even dealing with ring-buffer wraparound automatically.

## Pros and Cons

Based on its architectural design, `ufifo` has several distinctive advantages and some inherent limitations:

### Pros

- **Lock-Free Performance (`UFIFO_LOCK_NONE`)**: Achieves extreme high performance leveraging C11 memory barriers (`smp_load_acquire` / `smp_store_release`) for Single-Producer scenarios, completely bypassing kernel space.
- **Multi-Layer Crash Detection**: Combines robust mutex owner-death recovery, OFD lock-based liveness detection, and automatic dead-reader reaping.
- **Race-Free Lifecycle**: OFD file locking serializes initialization, attach, destroy, and force without sleep/retry polling inside the core.
- **Versatile Distribution Modes**: Natively supports both `SOLE` (competing consumers, perfect for worker pools) and `SHARED` (broadcast/pub-sub topologies).
- **Process-Shared Futex Waits**: Blocking and timed operations wait directly on shared RX/TX words, with no broker process or descriptor distribution protocol.
- **Zero-Allocation Record Hooks**: Custom callbacks (`recsize`, `recput`, `recget`) enable direct serialization/deserialization within the shared ring buffer, avoiding intermediate memory copies.
- **Lightweight & Dependency-Free**: Relies exclusively on standard C99/POSIX interfaces with no external third-party dependencies.

### Cons

- **Local IPC Only**: Restricted to communication within a single machine. Because it uses POSIX shared memory (`shm_open` and `mmap`), it cannot span across network boundaries.
- **Fixed Power-of-Two Capacity**: The buffer size is established during initialization and must be a power of two. It cannot dynamically allocate more memory or grow to accommodate traffic spikes once initialized.
- **Shared-Memory ABI Boundary**: Processes that exchange one FIFO must use the same shared-layout ABI. Attach rejects incompatible layouts before using their control fields.
- **Platform Specificity**: Designed around Linux-specific semantics such as futexes, `F_OFD_SETLK` liveness detection, POSIX shared memory, and robust mutexes. This significantly limits portability to non-Linux environments like macOS or Windows.
- **Setup Complexity**: Utilizing the advanced record mode and custom hooks requires writing specific serialization callbacks, making the initial setup slightly more complex than a basic pipe or POSIX Message Queue.

## Performance & Benchmarks

`ufifo` relies heavily on fine-grained C11 memory barriers (`smp_load_acquire` / `smp_store_release`) to maximize performance. 

- **Lock-Free Operation (`UFIFO_LOCK_NONE`)**: Achieves peak performance, isolating the memory barrier cost without contention. The ctrl/data dual-lock architecture ensures that even administrative operations (register/unregister) never block the hot data path.
- **Multithreaded Load**: Throughput remains highly efficient even under heavy load (MPSC scenarios) thanks to process-shared robust mutexes minimizing wait times.
- **Armed-Epoch Notification**: A producer or consumer only issues `FUTEX_WAKE` when the corresponding wait word is armed. With no waiter, notification is a read-only atomic check and does not dirty the shared cache line.

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
