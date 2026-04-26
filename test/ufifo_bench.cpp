/**
 * @file ufifo_bench.cpp
 * @brief Performance benchmark for ufifo library.
 *
 * Measures throughput and latency of put/get operations under different
 * configurations to evaluate the impact of replacing full memory barriers
 * (__sync_synchronize) with fine-grained C11 atomic operations
 * (acquire/release/relaxed).
 *
 * Key scenarios:
 *   1. Single-thread ping-pong (smallest overhead, isolates barrier cost)
 *   2. SPSC no-lock throughput (primary beneficiary of the optimization)
 *   3. SPSC with-lock throughput (mutex overhead dominates)
 *   4. Data size sweep (small vs large payloads)
 *   5. MPSC throughput (multi-producer contention)
 */

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#if defined(__linux__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <sched.h>
#endif

extern "C" {
#include "ufifo.h"
}

static constexpr unsigned int FIFO_SIZE = 65536; // 64 KB ring buffer
static constexpr int WARMUP_ITERS = 5000;

// Unique name generator
static std::atomic<int> g_name_counter{ 0 };
static char *bench_name(const char *prefix)
{
    static thread_local char buf[128];
    snprintf(buf, sizeof(buf), "bench_%s_%d_%d", prefix, g_name_counter++, getpid());
    return buf;
}

struct BenchResult {
    std::string name;
    int data_size;
    long long total_ops;
    double elapsed_sec;
    double ops_per_sec;
    double mb_per_sec;
    double avg_ns;
};

static bool g_json_output = false;

static bool g_pin_threads = true;
static std::vector<int> g_available_cpus;

static void init_affinity()
{
#if defined(__linux__)
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (sched_getaffinity(0, sizeof(cpu_set_t), &cpuset) == 0) {
        for (int i = 0; i < CPU_SETSIZE; i++) {
            if (CPU_ISSET(i, &cpuset)) {
                g_available_cpus.push_back(i);
            }
        }
    }
    if (g_available_cpus.empty()) {
        g_available_cpus.push_back(0);
    }
#endif
}

static void pin_current_thread(int logical_idx)
{
#if defined(__linux__)
    if (!g_pin_threads || g_available_cpus.empty())
        return;
    int phys_id = g_available_cpus[logical_idx % g_available_cpus.size()];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(phys_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
}

static void pin_thread(std::thread &t, int logical_idx)
{
#if defined(__linux__)
    if (!g_pin_threads || g_available_cpus.empty())
        return;
    int phys_id = g_available_cpus[logical_idx % g_available_cpus.size()];
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(phys_id, &cpuset);
    pthread_setaffinity_np(t.native_handle(), sizeof(cpu_set_t), &cpuset);
#endif
}

static void print_result(const BenchResult &r)
{
    if (g_json_output)
        return;
    printf("  %-40s | %6d B | %10lld ops | %8.3f s | %12.0f ops/s | %8.2f MB/s | %6.1f ns/op\n",
           r.name.c_str(),
           r.data_size,
           r.total_ops,
           r.elapsed_sec,
           r.ops_per_sec,
           r.mb_per_sec,
           r.avg_ns);
}

static void print_header()
{
    if (g_json_output)
        return;
    printf("  %-40s | %8s | %14s | %10s | %14s | %10s | %10s\n",
           "Benchmark",
           "DataSize",
           "TotalOps",
           "Elapsed",
           "Throughput",
           "Bandwidth",
           "Latency");
    printf("  %s\n", std::string(120, '-').c_str());
}

static void print_json(const std::vector<BenchResult> &results)
{
    printf("[\n");
    for (size_t i = 0; i < results.size(); ++i) {
        printf("  {\n");
        printf("    \"name\": \"%s\",\n", results[i].name.c_str());
        printf("    \"value\": %.0f,\n", results[i].ops_per_sec);
        printf("    \"unit\": \"ops/sec\",\n");
        printf(
            "    \"extra\": \"Latency: %.1f ns/op, Bandwidth: %.2f MB/s\"\n", results[i].avg_ns, results[i].mb_per_sec);
        printf("  }%s\n", (i == results.size() - 1) ? "" : ",");
    }
    printf("]\n");
}

// =============================================================================
// 1. Single-thread ping-pong: put one item then get one item
//    This isolates the put + get path cost with zero contention.
// =============================================================================
static BenchResult bench_pingpong(int data_size, ufifo_lock_e lock, int iters)
{
    const char *lock_name = (lock == UFIFO_LOCK_NONE) ? "nolock" : "locked";
    static char name_buf[128];
    snprintf(name_buf, sizeof(name_buf), "PingPong/%s/%dB", lock_name, data_size);

    char *fifo_name = bench_name("pp");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = lock;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    ufifo_open(fifo_name, &init, &fifo);

    std::vector<char> wbuf(data_size, 0xAA);
    std::vector<char> rbuf(data_size, 0);

    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++) {
        ufifo_put(fifo, wbuf.data(), data_size);
        ufifo_get(fifo, rbuf.data(), data_size);
    }

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; i++) {
        ufifo_put(fifo, wbuf.data(), data_size);
        ufifo_get(fifo, rbuf.data(), data_size);
    }
    auto end = std::chrono::high_resolution_clock::now();

    double elapsed = std::chrono::duration<double>(end - start).count();
    long long total_ops = (long long)iters * 2; // put + get = 2 ops

    ufifo_destroy(fifo);

    return BenchResult{
        name_buf,
        data_size,
        total_ops,
        elapsed,
        total_ops / elapsed,
        (double)iters * data_size * 2.0 / elapsed / (1024.0 * 1024.0),
        elapsed * 1e9 / total_ops,
    };
}

// =============================================================================
// 2. SPSC throughput: producer and consumer on separate threads
// =============================================================================
static BenchResult bench_spsc(int data_size, ufifo_lock_e lock, int total_items)
{
    const char *lock_name = (lock == UFIFO_LOCK_NONE) ? "nolock" : "locked";
    static char name_buf[128];
    snprintf(name_buf, sizeof(name_buf), "SPSC/%s/%dB", lock_name, data_size);

    char *fifo_name = bench_name("spsc");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = lock;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    ufifo_open(fifo_name, &init, &fifo);

    std::vector<char> wbuf(data_size, 0xBB);
    std::vector<char> rbuf(data_size, 0);

    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++) {
        ufifo_put(fifo, wbuf.data(), data_size);
        ufifo_get(fifo, rbuf.data(), data_size);
    }

    std::atomic<bool> producer_done{ false };

    auto start = std::chrono::high_resolution_clock::now();

    std::thread producer([&]() {
        int count = 0;
        while (count < total_items) {
            if (ufifo_put(fifo, wbuf.data(), data_size) > 0) {
                count++;
            } else {
                std::this_thread::yield();
            }
        }
        producer_done.store(true, std::memory_order_release);
    });
    pin_thread(producer, 0);

    std::thread consumer([&]() {
        int count = 0;
        while (count < total_items) {
            if (ufifo_get(fifo, rbuf.data(), data_size) > 0) {
                count++;
            } else {
                std::this_thread::yield();
            }
        }
    });
    pin_thread(consumer, 1);

    producer.join();
    consumer.join();
    auto end = std::chrono::high_resolution_clock::now();

    double elapsed = std::chrono::duration<double>(end - start).count();
    long long total_ops = (long long)total_items * 2;

    ufifo_destroy(fifo);

    return BenchResult{
        name_buf,
        data_size,
        total_ops,
        elapsed,
        total_ops / elapsed,
        (double)total_items * data_size * 2.0 / elapsed / (1024.0 * 1024.0),
        elapsed * 1e9 / total_ops,
    };
}

// =============================================================================
// 3. Burst throughput: fill the FIFO then drain it (no contention)
//    Measures raw sequential put/get without inter-thread waiting.
// =============================================================================
static BenchResult bench_burst(int data_size, ufifo_lock_e lock, int rounds)
{
    const char *lock_name = (lock == UFIFO_LOCK_NONE) ? "nolock" : "locked";
    static char name_buf[128];
    snprintf(name_buf, sizeof(name_buf), "Burst/%s/%dB", lock_name, data_size);

    char *fifo_name = bench_name("burst");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = lock;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    ufifo_open(fifo_name, &init, &fifo);

    std::vector<char> wbuf(data_size, 0xCC);
    std::vector<char> rbuf(data_size, 0);

    // Items that fit in one burst
    int items_per_burst = (int)(FIFO_SIZE / data_size);
    if (items_per_burst < 1)
        items_per_burst = 1;

    // Warmup
    for (int w = 0; w < WARMUP_ITERS / items_per_burst + 1; w++) {
        for (int i = 0; i < items_per_burst; i++)
            ufifo_put(fifo, wbuf.data(), data_size);
        for (int i = 0; i < items_per_burst; i++)
            ufifo_get(fifo, rbuf.data(), data_size);
    }

    long long total_ops = 0;
    auto start = std::chrono::high_resolution_clock::now();

    for (int r = 0; r < rounds; r++) {
        // Burst write
        for (int i = 0; i < items_per_burst; i++) {
            ufifo_put(fifo, wbuf.data(), data_size);
        }
        // Burst read
        for (int i = 0; i < items_per_burst; i++) {
            ufifo_get(fifo, rbuf.data(), data_size);
        }
        total_ops += items_per_burst * 2;
    }

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();

    ufifo_destroy(fifo);

    return BenchResult{
        name_buf,
        data_size,
        total_ops,
        elapsed,
        total_ops / elapsed,
        (double)total_ops / 2.0 * data_size * 2.0 / elapsed / (1024.0 * 1024.0),
        elapsed * 1e9 / total_ops,
    };
}

// =============================================================================
// 4. MPSC throughput: multiple producers, single consumer
// =============================================================================
static BenchResult bench_mpsc(int data_size, int num_producers, int items_per_producer)
{
    static char name_buf[128];
    snprintf(name_buf, sizeof(name_buf), "MPSC/%dP/%dB", num_producers, data_size);

    char *fifo_name = bench_name("mpsc");
    int total_handles = num_producers + 1; // producers + 1 consumer

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = total_handles;

    ufifo_t *fifo = nullptr;
    ufifo_open(fifo_name, &init, &fifo);

    int total_items = num_producers * items_per_producer;
    std::vector<char> wbuf(data_size, 0xDD);
    std::vector<char> rbuf(data_size, 0);

    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++) {
        ufifo_put(fifo, wbuf.data(), data_size);
        ufifo_get(fifo, rbuf.data(), data_size);
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Launch producers
    std::vector<std::thread> threads;
    for (int p = 0; p < num_producers; p++) {
        threads.emplace_back([&]() {
            int count = 0;
            while (count < items_per_producer) {
                if (ufifo_put(fifo, wbuf.data(), data_size) > 0) {
                    count++;
                } else {
                    std::this_thread::yield();
                }
            }
        });
        pin_thread(threads.back(), p + 1);
    }

    // Consumer
    threads.emplace_back([&]() {
        int count = 0;
        while (count < total_items) {
            if (ufifo_get(fifo, rbuf.data(), data_size) > 0) {
                count++;
            } else {
                std::this_thread::yield();
            }
        }
    });
    pin_thread(threads.back(), 0);

    for (auto &t : threads)
        t.join();

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    long long total_ops = (long long)total_items * 2;

    ufifo_destroy(fifo);

    return BenchResult{
        name_buf,
        data_size,
        total_ops,
        elapsed,
        total_ops / elapsed,
        (double)total_items * data_size * 2.0 / elapsed / (1024.0 * 1024.0),
        elapsed * 1e9 / total_ops,
    };
}

// =============================================================================
// 5. Shared-mode (broadcast) SPSC throughput
// =============================================================================
static BenchResult bench_shared_spsc(int data_size, int total_items)
{
    static char name_buf[128];
    snprintf(name_buf, sizeof(name_buf), "SharedSPSC/%dB", data_size);

    char *fifo_name = bench_name("shspsc");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    ufifo_t *producer = nullptr;
    ufifo_open(fifo_name, &init, &producer);

    ufifo_t *consumer = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_open(fifo_name, &attach, &consumer);

    std::vector<char> wbuf(data_size, 0xEE);
    std::vector<char> rbuf(data_size, 0);

    // Warmup
    std::thread prod_warmup([&]() {
        int count = 0;
        while (count < WARMUP_ITERS) {
            if (ufifo_put(producer, wbuf.data(), data_size) > 0) {
                ufifo_get(producer, rbuf.data(), data_size);
                count++;
            } else {
                std::this_thread::yield();
            }
        }
    });

    std::thread cons_warmup([&]() {
        int count = 0;
        while (count < WARMUP_ITERS) {
            if (ufifo_get(consumer, rbuf.data(), data_size) > 0) {
                count++;
            } else {
                std::this_thread::yield();
            }
        }
    });

    prod_warmup.join();
    cons_warmup.join();

    auto start = std::chrono::high_resolution_clock::now();

    std::thread prod_thread([&]() {
        int count = 0;
        while (count < total_items) {
            if (ufifo_put(producer, wbuf.data(), data_size) > 0) {
                // Producer must also consume to advance its own out pointer
                ufifo_get(producer, rbuf.data(), data_size);
                count++;
            } else {
                std::this_thread::yield();
            }
        }
    });
    pin_thread(prod_thread, 0);

    std::thread cons_thread([&]() {
        int count = 0;
        while (count < total_items) {
            if (ufifo_get(consumer, rbuf.data(), data_size) > 0) {
                count++;
            } else {
                std::this_thread::yield();
            }
        }
    });
    pin_thread(cons_thread, 1);

    prod_thread.join();
    cons_thread.join();

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();
    long long total_ops = (long long)total_items * 2;

    ufifo_close(consumer);
    ufifo_destroy(producer);

    return BenchResult{
        name_buf,
        data_size,
        total_ops,
        elapsed,
        total_ops / elapsed,
        (double)total_items * data_size * 2.0 / elapsed / (1024.0 * 1024.0),
        elapsed * 1e9 / total_ops,
    };
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char **argv)
{
    int scale = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            g_json_output = true;
        } else if (strcmp(argv[i], "--no-pin") == 0) {
            g_pin_threads = false;
        } else {
            scale = atoi(argv[i]);
            if (scale < 1)
                scale = 1;
        }
    }

    if (g_pin_threads) {
        init_affinity();
        pin_current_thread(0);
    }

    if (!g_json_output) {
        printf("\n=== ufifo Performance Benchmark (scale=%d) ===\n", scale);
        printf("System Info:\n");
        printf("  Hardware Concurrency (Total system CPUs): %u\n", std::thread::hardware_concurrency());
#if defined(__linux__)
        printf("  Thread Pinning (Affinity): %s\n", g_pin_threads ? "Enabled" : "Disabled");
        printf("  Available logical CPUs for this process: %zu\n", g_available_cpus.size());
        if (g_pin_threads && !g_available_cpus.empty()) {
            printf("  Available CPU IDs: [");
            for (size_t i = 0; i < g_available_cpus.size(); ++i) {
                printf("%d%s", g_available_cpus[i], (i == g_available_cpus.size() - 1) ? "" : ", ");
            }
            printf("]\n");
        }
#else
        printf("  Thread Pinning (Affinity): Disabled (Unsupported OS)\n");
#endif
        printf("\n");
    }

    std::vector<BenchResult> results;

    // --- Ping-pong across data sizes ---
    if (!g_json_output)
        printf("[1] Single-thread Ping-Pong (put+get round-trip, zero contention)\n");
    print_header();
    // Short fast-path for nolock to avoid thermal throttling, longer for locked
    int pp_iters = 500000 * scale;
    for (int sz : { 4, 64, 256, 1024, 4096 }) {
        auto r = bench_pingpong(sz, UFIFO_LOCK_NONE, pp_iters);
        print_result(r);
        results.push_back(r);
    }
    for (int sz : { 4, 64, 256, 1024, 4096 }) {
        auto r = bench_pingpong(sz, UFIFO_LOCK_THREAD, pp_iters * 4); // Smoother variance
        print_result(r);
        results.push_back(r);
    }
    if (!g_json_output)
        printf("\n");

    // --- SPSC throughput ---
    if (!g_json_output)
        printf("[2] SPSC Throughput (producer + consumer threads)\n");
    print_header();
    int spsc_items = 500000 * scale;
    for (int sz : { 4, 64, 256, 1024 }) {
        auto r = bench_spsc(sz, UFIFO_LOCK_NONE, spsc_items);
        print_result(r);
        results.push_back(r);
    }
    for (int sz : { 4, 64, 256, 1024 }) {
        // Multi-threaded locked needs longer runs to offset thread-spawn overhead
        auto r = bench_spsc(sz, UFIFO_LOCK_THREAD, spsc_items * 3);
        print_result(r);
        results.push_back(r);
    }
    if (!g_json_output)
        printf("\n");

    // --- Burst throughput ---
    if (!g_json_output)
        printf("[3] Burst Throughput (fill then drain, single thread)\n");
    print_header();
    int burst_rounds = 2000 * scale;
    for (int sz : { 4, 64, 256, 1024 }) {
        auto r = bench_burst(sz, UFIFO_LOCK_NONE, burst_rounds);
        print_result(r);
        results.push_back(r);
    }
    for (int sz : { 4, 64, 256, 1024 }) {
        auto r = bench_burst(sz, UFIFO_LOCK_THREAD, burst_rounds * 4);
        print_result(r);
        results.push_back(r);
    }
    if (!g_json_output)
        printf("\n");

    // --- MPSC throughput ---
    if (!g_json_output)
        printf("[4] MPSC Throughput (multi-producer, single consumer)\n");
    print_header();
    // Heavy contention, runs longer to smooth out variance
    int mpsc_per_prod = 500000 * scale;
    for (int sz : { 4, 64, 256 }) {
        auto r = bench_mpsc(sz, 2, mpsc_per_prod);
        print_result(r);
        results.push_back(r);
    }
    for (int sz : { 4, 64, 256 }) {
        auto r = bench_mpsc(sz, 4, mpsc_per_prod);
        print_result(r);
        results.push_back(r);
    }
    if (!g_json_output)
        printf("\n");

    // --- Shared-mode SPSC ---
    if (!g_json_output)
        printf("[5] Shared-mode SPSC Throughput (broadcast mode)\n");
    print_header();
    int shared_items = 500000 * scale;
    for (int sz : { 4, 64, 256, 1024 }) {
        auto r = bench_shared_spsc(sz, shared_items);
        print_result(r);
        results.push_back(r);
    }
    if (!g_json_output) {
        printf("\n");
        printf("=== Summary: %zu benchmarks completed ===\n\n", results.size());
        printf("Key metrics to compare before/after the commit:\n");
        printf("  - PingPong/nolock/4B: isolates barrier-only cost (highest expected improvement)\n");
        printf("  - SPSC/nolock/*: realistic SPSC throughput (5-15%% improvement expected)\n");
        printf("  - SPSC/locked/*: mutex-dominated path (<3%% improvement expected)\n");
        printf("  - Burst/nolock/*: sequential fill-drain without contention\n");
        printf("  - MPSC/*: multi-producer contention (mutex-dominated)\n");
        printf("  - SharedSPSC/*: shared-mode broadcast (no improvement expected)\n\n");
    } else {
        print_json(results);
    }

    return 0;
}
