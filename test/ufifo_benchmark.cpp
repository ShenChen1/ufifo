#include <benchmark/benchmark.h>
#include <thread>
#include <vector>
#include <string>
#include <atomic>
#include <unistd.h>
#include "ufifo.h"

static std::string GenerateName(const char *prefix) {
    static std::atomic<int> counter{0};
    return std::string(prefix) + "_" + std::to_string(counter++) + "_" + std::to_string(getpid());
}

static void BM_Ufifo_SPSC_Throughput(benchmark::State& state) {
    std::string name = GenerateName("spsc_bm");

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 1024 * 1024; // 1MB buffer
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2; // 1 producer, 1 consumer

    ufifo_t *producer = nullptr;
    if (ufifo_open(const_cast<char *>(name.c_str()), &init, &producer) != 0) {
        state.SkipWithError("Failed to create ufifo");
        return;
    }

    ufifo_t *consumer = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    if (ufifo_open(const_cast<char *>(name.c_str()), &attach, &consumer) != 0) {
        state.SkipWithError("Failed to attach to ufifo");
        ufifo_destroy(producer);
        return;
    }

    const size_t msg_size = state.range(0);
    std::vector<char> msg(msg_size, 'x');

    std::atomic<bool> producer_ready{false};
    std::atomic<bool> producer_done{false};

    // Consumer runs in the benchmark thread
    std::thread producer_thread([&]() {
        producer_ready = true;

        while (!producer_done.load(std::memory_order_relaxed)) {
            ufifo_put(producer, msg.data(), msg_size);
            // Ignore put failures (queue full) in tight loop, just spin
        }
    });

    // Wait for producer to spin up
    while (!producer_ready) {
        std::this_thread::yield();
    }

    std::vector<char> rx_buf(msg_size);
    size_t total_bytes = 0;

    for (auto _ : state) {
        // Consumer loop
        unsigned int ret = ufifo_get(consumer, rx_buf.data(), msg_size);
        if (ret > 0) {
            total_bytes += ret;
        } else {
            // Queue empty, just spin/yield
            // We use Pause() to not count empty spins in the timing?
            // Actually Google benchmark measures wall clock of the `for (auto _ : state)` loop.
            // If the queue is empty, we just continue.
        }
    }

    producer_done.store(true, std::memory_order_relaxed);
    producer_thread.join();

    state.SetBytesProcessed(total_bytes);

    ufifo_close(consumer);
    ufifo_destroy(producer);
}

// Test message sizes: 64B, 256B, 1KB, 4KB
BENCHMARK(BM_Ufifo_SPSC_Throughput)
    ->RangeMultiplier(4)
    ->Range(64, 4096)
    ->UseRealTime();

BENCHMARK_MAIN();
