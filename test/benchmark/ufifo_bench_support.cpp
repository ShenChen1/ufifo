#include "ufifo_bench.hpp"

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
void PinNativeThread(pthread_t thread, int logical_index)
{
    if (!g_pin_threads || available_cpus.empty())
        return;

    const int physical_id = available_cpus[logical_index % available_cpus.size()];
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(physical_id, &cpu_set);
    (void)pthread_setaffinity_np(thread, sizeof(cpu_set), &cpu_set);
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

void PinCurrentThread(int logical_index)
{
#if defined(__linux__)
    PinNativeThread(pthread_self(), logical_index);
#else
    (void)logical_index;
#endif
}

void PinThread(std::thread &thread, int logical_index)
{
#if defined(__linux__)
    PinNativeThread(thread.native_handle(), logical_index);
#else
    (void)thread;
    (void)logical_index;
#endif
}

const std::vector<int> &AvailableCpus()
{
    return available_cpus;
}

void PrintResult(const BenchResult &result)
{
    if (g_json_output)
        return;
    printf("  %-40s | %6d B | %10lld ops | %8.3f s | %12.0f ops/s | %8.2f MB/s | %6.1f ns/op\n",
           result.name.c_str(),
           result.data_size,
           result.total_ops,
           result.elapsed_sec,
           result.ops_per_sec,
           result.mb_per_sec,
           result.avg_ns);
}

void PrintHeader()
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

void PrintJson(const std::vector<BenchResult> &results)
{
    printf("[\n");
    for (size_t index = 0; index < results.size(); index++) {
        const BenchResult &result = results[index];
        printf("  {\n");
        printf("    \"name\": \"%s\",\n", result.name.c_str());
        printf("    \"value\": %.0f,\n", result.ops_per_sec);
        printf("    \"unit\": \"ops/sec\",\n");
        printf("    \"extra\": \"Latency: %.1f ns/op, Bandwidth: %.2f MB/s\"\n",
               result.avg_ns,
               result.mb_per_sec);
        printf("  }%s\n", index + 1 == results.size() ? "" : ",");
    }
    printf("]\n");
}
