#include "ufifo_bench.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

constexpr unsigned int FIFO_SIZE = 65536;
constexpr int WARMUP_ITERATIONS = 5000;

std::atomic<int> name_counter{ 0 };

std::string LockName(ufifo_lock_e lock)
{
    return lock == UFIFO_LOCK_NONE ? "nolock" : "locked";
}

std::string BenchmarkName(const char *prefix)
{
    return std::string("bench_") + prefix + "_" + std::to_string(name_counter++) + "_" + std::to_string(getpid());
}

ufifo_t *OpenFifo(
    const char *prefix, ufifo_lock_e lock, ufifo_data_mode_e mode, size_t max_users, std::string *opened_name = nullptr)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = FIFO_SIZE;
    init.alloc.force = 1;
    init.alloc.lock = lock;
    init.alloc.data_mode = mode;
    init.alloc.max_users = max_users;

    ufifo_t *fifo = nullptr;
    const std::string name = BenchmarkName(prefix);
    const int result = ufifo_open(name.c_str(), &init, &fifo);
    if (result != 0) {
        fprintf(stderr, "ufifo_bench: cannot create %s: %d\n", prefix, result);
        exit(EXIT_FAILURE);
    }
    if (opened_name != nullptr)
        *opened_name = name;
    return fifo;
}

BenchResult MakeResult(const std::string &name,
                       int data_size,
                       long long total_ops,
                       const std::chrono::high_resolution_clock::duration &duration)
{
    const double elapsed = std::chrono::duration<double>(duration).count();
    const double bytes = static_cast<double>(total_ops) * data_size;
    return { name,
             data_size,
             total_ops,
             elapsed,
             total_ops / elapsed,
             bytes / elapsed / (1024.0 * 1024.0),
             elapsed * 1e9 / total_ops };
}

} // namespace

BenchResult RunPingPongBenchmark(int data_size, ufifo_lock_e lock, int iterations)
{
    ufifo_t *fifo = OpenFifo("pp", lock, UFIFO_DATA_SOLE, 1);
    std::vector<char> write_buffer(data_size, static_cast<char>(0xAA));
    std::vector<char> read_buffer(data_size);

    for (int index = 0; index < WARMUP_ITERATIONS; index++) {
        ufifo_put(fifo, write_buffer.data(), data_size);
        ufifo_get(fifo, read_buffer.data(), data_size);
    }

    const auto start = std::chrono::high_resolution_clock::now();
    for (int index = 0; index < iterations; index++) {
        ufifo_put(fifo, write_buffer.data(), data_size);
        ufifo_get(fifo, read_buffer.data(), data_size);
    }
    const auto duration = std::chrono::high_resolution_clock::now() - start;
    ufifo_destroy(fifo);

    const std::string name = "PingPong/" + LockName(lock) + "/" + std::to_string(data_size) + "B";
    return MakeResult(name, data_size, static_cast<long long>(iterations) * 2, duration);
}

BenchResult RunSpscBenchmark(int data_size, ufifo_lock_e lock, int total_items)
{
    ufifo_t *fifo = OpenFifo("spsc", lock, UFIFO_DATA_SOLE, 1);
    std::vector<char> write_buffer(data_size, static_cast<char>(0xBB));
    std::vector<char> read_buffer(data_size);
    for (int index = 0; index < WARMUP_ITERATIONS; index++) {
        ufifo_put(fifo, write_buffer.data(), data_size);
        ufifo_get(fifo, read_buffer.data(), data_size);
    }

    const auto start = std::chrono::high_resolution_clock::now();
    std::thread producer([&]() {
        for (int count = 0; count < total_items;) {
            if (ufifo_put(fifo, write_buffer.data(), data_size) > 0)
                count++;
            else
                std::this_thread::yield();
        }
    });
    PinThread(producer, 0);
    std::thread consumer([&]() {
        for (int count = 0; count < total_items;) {
            if (ufifo_get(fifo, read_buffer.data(), data_size) > 0)
                count++;
            else
                std::this_thread::yield();
        }
    });
    PinThread(consumer, 1);
    producer.join();
    consumer.join();
    const auto duration = std::chrono::high_resolution_clock::now() - start;
    ufifo_destroy(fifo);

    const std::string name = "SPSC/" + LockName(lock) + "/" + std::to_string(data_size) + "B";
    return MakeResult(name, data_size, static_cast<long long>(total_items) * 2, duration);
}

BenchResult RunBurstBenchmark(int data_size, ufifo_lock_e lock, int rounds)
{
    ufifo_t *fifo = OpenFifo("burst", lock, UFIFO_DATA_SOLE, 1);
    std::vector<char> write_buffer(data_size, static_cast<char>(0xCC));
    std::vector<char> read_buffer(data_size);
    const int items_per_burst = std::max(1, static_cast<int>(FIFO_SIZE / data_size));
    for (int warmup = 0; warmup < WARMUP_ITERATIONS / items_per_burst + 1; warmup++) {
        for (int item = 0; item < items_per_burst; item++)
            ufifo_put(fifo, write_buffer.data(), data_size);
        for (int item = 0; item < items_per_burst; item++)
            ufifo_get(fifo, read_buffer.data(), data_size);
    }

    const auto start = std::chrono::high_resolution_clock::now();
    for (int round = 0; round < rounds; round++) {
        for (int item = 0; item < items_per_burst; item++)
            ufifo_put(fifo, write_buffer.data(), data_size);
        for (int item = 0; item < items_per_burst; item++)
            ufifo_get(fifo, read_buffer.data(), data_size);
    }
    const auto duration = std::chrono::high_resolution_clock::now() - start;
    ufifo_destroy(fifo);

    const long long total_ops = static_cast<long long>(rounds) * items_per_burst * 2;
    const std::string name = "Burst/" + LockName(lock) + "/" + std::to_string(data_size) + "B";
    return MakeResult(name, data_size, total_ops, duration);
}

BenchResult RunMpscBenchmark(int data_size, int producer_count, int items_per_producer)
{
    ufifo_t *fifo = OpenFifo("mpsc", UFIFO_LOCK_THREAD, UFIFO_DATA_SOLE, producer_count + 1);
    std::vector<char> write_buffer(data_size, static_cast<char>(0xDD));
    std::vector<char> read_buffer(data_size);
    for (int index = 0; index < WARMUP_ITERATIONS; index++) {
        ufifo_put(fifo, write_buffer.data(), data_size);
        ufifo_get(fifo, read_buffer.data(), data_size);
    }

    const int total_items = producer_count * items_per_producer;
    const auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::thread> threads;
    for (int producer_index = 0; producer_index < producer_count; producer_index++) {
        threads.emplace_back([&]() {
            for (int count = 0; count < items_per_producer;) {
                if (ufifo_put(fifo, write_buffer.data(), data_size) > 0)
                    count++;
                else
                    std::this_thread::yield();
            }
        });
        PinThread(threads.back(), producer_index + 1);
    }
    threads.emplace_back([&]() {
        for (int count = 0; count < total_items;) {
            if (ufifo_get(fifo, read_buffer.data(), data_size) > 0)
                count++;
            else
                std::this_thread::yield();
        }
    });
    PinThread(threads.back(), 0);
    for (auto &thread : threads)
        thread.join();
    const auto duration = std::chrono::high_resolution_clock::now() - start;
    ufifo_destroy(fifo);

    const std::string name = "MPSC/" + std::to_string(producer_count) + "P/" + std::to_string(data_size) + "B";
    return MakeResult(name, data_size, static_cast<long long>(total_items) * 2, duration);
}

BenchResult RunSharedSpscBenchmark(int data_size, int total_items)
{
    std::string fifo_name;
    ufifo_t *producer = OpenFifo("shspsc", UFIFO_LOCK_NONE, UFIFO_DATA_SHARED, 2, &fifo_name);
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *consumer = nullptr;
    if (ufifo_open(fifo_name.c_str(), &attach, &consumer) != 0) {
        fprintf(stderr, "ufifo_bench: cannot attach shared consumer\n");
        exit(EXIT_FAILURE);
    }

    std::vector<char> write_buffer(data_size, static_cast<char>(0xEE));
    std::vector<char> producer_read_buffer(data_size);
    std::vector<char> consumer_read_buffer(data_size);
    auto run_producer = [&](int count_limit) {
        for (int count = 0; count < count_limit;) {
            if (ufifo_put(producer, write_buffer.data(), data_size) > 0) {
                ufifo_get(producer, producer_read_buffer.data(), data_size);
                count++;
            } else {
                std::this_thread::yield();
            }
        }
    };
    auto run_consumer = [&](int count_limit) {
        for (int count = 0; count < count_limit;) {
            if (ufifo_get(consumer, consumer_read_buffer.data(), data_size) > 0)
                count++;
            else
                std::this_thread::yield();
        }
    };

    std::thread warmup_producer(run_producer, WARMUP_ITERATIONS);
    std::thread warmup_consumer(run_consumer, WARMUP_ITERATIONS);
    warmup_producer.join();
    warmup_consumer.join();

    const auto start = std::chrono::high_resolution_clock::now();
    std::thread producer_thread(run_producer, total_items);
    PinThread(producer_thread, 0);
    std::thread consumer_thread(run_consumer, total_items);
    PinThread(consumer_thread, 1);
    producer_thread.join();
    consumer_thread.join();
    const auto duration = std::chrono::high_resolution_clock::now() - start;

    ufifo_close(consumer);
    ufifo_destroy(producer);
    const std::string name = "SharedSPSC/" + std::to_string(data_size) + "B";
    return MakeResult(name, data_size, static_cast<long long>(total_items) * 2, duration);
}
