#include "ufifo_bench.hpp"

#include <algorithm>
#include <cstdio>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#endif

bool g_json_output = false;
bool g_pin_threads = true;

namespace {

std::vector<int> available_cpus;

#if defined(__linux__)
int PinNativeThread(pthread_t thread, int logical_index)
{
    if (!g_pin_threads || available_cpus.empty())
        return 0;

    const int physical_id = available_cpus[logical_index % available_cpus.size()];
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(physical_id, &cpu_set);
    return pthread_setaffinity_np(thread, sizeof(cpu_set), &cpu_set);
}
#endif

} // namespace

void InitializeAffinity()
{
#if defined(__linux__)
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    if (sched_getaffinity(0, sizeof(cpu_set), &cpu_set) == 0) {
        for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
            if (CPU_ISSET(cpu, &cpu_set))
                available_cpus.push_back(cpu);
        }
    }
    if (available_cpus.empty())
        available_cpus.push_back(0);
#endif
}

int PinCurrentThread(int logical_index)
{
#if defined(__linux__)
    return PinNativeThread(pthread_self(), logical_index);
#else
    (void)logical_index;
    return 0;
#endif
}

void BenchStartGate::WorkerReadyAndWait()
{
    std::unique_lock<std::mutex> lock(mutex_);
    ready_count_++;
    condition_.notify_all();
    condition_.wait(lock, [&]() { return started_; });
}

bool BenchStartGate::WaitUntilReady(size_t expected, std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(mutex_);
    return condition_.wait_for(lock, timeout, [&]() { return ready_count_ >= expected; });
}

void BenchStartGate::Start()
{
    std::lock_guard<std::mutex> lock(mutex_);
    started_ = true;
    condition_.notify_all();
}

const std::vector<int> &AvailableCpus()
{
    return available_cpus;
}

BenchResult SummarizeBenchResults(const std::vector<BenchResult> &samples)
{
    if (samples.empty())
        return {};

    std::vector<BenchResult> sorted = samples;
    std::sort(sorted.begin(), sorted.end(), [](const BenchResult &left, const BenchResult &right) {
        return left.ops_per_sec < right.ops_per_sec;
    });
    BenchResult summary = sorted[sorted.size() / 2];
    summary.sample_count = static_cast<int>(sorted.size());
    if (summary.ops_per_sec > 0.0)
        summary.spread_pct = (sorted.back().ops_per_sec - sorted.front().ops_per_sec) / summary.ops_per_sec * 100.0;
    return summary;
}

void PrintResult(const BenchResult &result)
{
    if (g_json_output)
        return;
    printf("  %-40s | %6d B | %10lld ops | %8.3f s | %12.0f ops/s | %8.2f MB/s | %6.1f ns/op | %2d | %6.1f%%\n",
           result.name.c_str(),
           result.data_size,
           result.total_ops,
           result.elapsed_sec,
           result.ops_per_sec,
           result.mb_per_sec,
           result.avg_ns,
           result.sample_count,
           result.spread_pct);
}

void PrintHeader()
{
    if (g_json_output)
        return;
    printf("  %-40s | %8s | %14s | %10s | %14s | %10s | %10s | %2s | %7s\n",
           "Benchmark",
           "DataSize",
           "TotalOps",
           "Elapsed",
           "Throughput",
           "Bandwidth",
           "Latency",
           "N",
           "Spread");
    printf("  %s\n", std::string(136, '-').c_str());
}

void PrintJson(const std::vector<BenchResult> &results)
{
    printf("[\n");
    for (size_t index = 0; index < results.size(); index++) {
        const BenchResult &result = results[index];
        printf("  {\n");
        printf("    \"name\": \"%s\",\n", result.name.c_str());
        printf("    \"value\": %.0f,\n", result.ops_per_sec);
        printf("    \"unit\": \"ops/sec\",\n");
        printf("    \"extra\": \"Latency: %.1f ns/op, Bandwidth: %.2f MB/s, Samples: %d, Spread: %.1f%%\"\n",
               result.avg_ns,
               result.mb_per_sec,
               result.sample_count,
               result.spread_pct);
        printf("  }%s\n", index + 1 == results.size() ? "" : ",");
    }
    printf("]\n");
}
