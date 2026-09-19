#include "ufifo_bench.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace {

struct Options {
    int scale = 1;
};

Options ParseOptions(int argc, char **argv)
{
    Options options;
    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--json") == 0)
            g_json_output = true;
        else if (strcmp(argv[index], "--no-pin") == 0)
            g_pin_threads = false;
        else
            options.scale = std::max(1, atoi(argv[index]));
    }
    return options;
}

void PrintSystemInfo(int scale)
{
    if (g_json_output)
        return;

    printf("\n=== ufifo Performance Benchmark (scale=%d) ===\n", scale);
    printf("System Info:\n");
    printf("  Hardware Concurrency (Total system CPUs): %u\n", std::thread::hardware_concurrency());
#if defined(__linux__)
    printf("  Thread Pinning (Affinity): %s\n", g_pin_threads ? "Enabled" : "Disabled");
    printf("  Available logical CPUs for this process: %zu\n", AvailableCpus().size());
    if (g_pin_threads && !AvailableCpus().empty()) {
        printf("  Available CPU IDs: [");
        for (size_t index = 0; index < AvailableCpus().size(); index++)
            printf("%d%s", AvailableCpus()[index], index + 1 == AvailableCpus().size() ? "" : ", ");
        printf("]\n");
    }
#else
    printf("  Thread Pinning (Affinity): Disabled (Unsupported OS)\n");
#endif
    printf("\n");
}

void AddResult(std::vector<BenchResult> &results, BenchResult result)
{
    PrintResult(result);
    results.push_back(std::move(result));
}

void RunPingPongSection(int scale, std::vector<BenchResult> &results)
{
    if (!g_json_output)
        printf("[1] Single-thread Ping-Pong (put+get round-trip, zero contention)\n");
    PrintHeader();
    const int iterations = 500000 * scale;
    for (int size : { 4, 64, 256, 1024, 4096 })
        AddResult(results, RunPingPongBenchmark(size, UFIFO_LOCK_NONE, iterations));
    for (int size : { 4, 64, 256, 1024, 4096 })
        AddResult(results, RunPingPongBenchmark(size, UFIFO_LOCK_THREAD, iterations * 4));
    if (!g_json_output)
        printf("\n");
}

void RunSpscSection(int scale, std::vector<BenchResult> &results)
{
    if (!g_json_output)
        printf("[2] SPSC Throughput (producer + consumer threads)\n");
    PrintHeader();
    const int items = 500000 * scale;
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunSpscBenchmark(size, UFIFO_LOCK_NONE, items));
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunSpscBenchmark(size, UFIFO_LOCK_THREAD, items * 3));
    if (!g_json_output)
        printf("\n");
}

void RunBurstSection(int scale, std::vector<BenchResult> &results)
{
    if (!g_json_output)
        printf("[3] Burst Throughput (fill then drain, single thread)\n");
    PrintHeader();
    const int rounds = 2000 * scale;
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunBurstBenchmark(size, UFIFO_LOCK_NONE, rounds));
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunBurstBenchmark(size, UFIFO_LOCK_THREAD, rounds * 4));
    if (!g_json_output)
        printf("\n");
}

void RunMpscSection(int scale, std::vector<BenchResult> &results)
{
    if (!g_json_output)
        printf("[4] MPSC Throughput (multi-producer, single consumer)\n");
    PrintHeader();
    const int items_per_producer = 500000 * scale;
    for (int size : { 4, 64, 256 })
        AddResult(results, RunMpscBenchmark(size, 2, items_per_producer));
    for (int size : { 4, 64, 256 })
        AddResult(results, RunMpscBenchmark(size, 4, items_per_producer));
    if (!g_json_output)
        printf("\n");
}

void RunSharedSpscSection(int scale, std::vector<BenchResult> &results)
{
    if (!g_json_output)
        printf("[5] Shared-mode SPSC Throughput (broadcast mode)\n");
    PrintHeader();
    const int items = 500000 * scale;
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunSharedSpscBenchmark(size, items));
}

void PrintSummary(const std::vector<BenchResult> &results)
{
    if (g_json_output) {
        PrintJson(results);
        return;
    }
    printf("\n=== Summary: %zu benchmarks completed ===\n\n", results.size());
    printf("Key metrics to compare before/after the commit:\n");
    printf("  - PingPong/nolock/4B: isolates barrier-only cost (highest expected improvement)\n");
    printf("  - SPSC/nolock/*: realistic SPSC throughput (5-15%% improvement expected)\n");
    printf("  - SPSC/locked/*: mutex-dominated path (<3%% improvement expected)\n");
    printf("  - Burst/nolock/*: sequential fill-drain without contention\n");
    printf("  - MPSC/*: multi-producer contention (mutex-dominated)\n");
    printf("  - SharedSPSC/*: shared-mode broadcast (no improvement expected)\n\n");
}

} // namespace

int main(int argc, char **argv)
{
    const Options options = ParseOptions(argc, argv);
    if (g_pin_threads) {
        InitializeAffinity();
        PinCurrentThread(0);
    }
    PrintSystemInfo(options.scale);

    std::vector<BenchResult> results;
    RunPingPongSection(options.scale, results);
    RunSpscSection(options.scale, results);
    RunBurstSection(options.scale, results);
    RunMpscSection(options.scale, results);
    RunSharedSpscSection(options.scale, results);
    PrintSummary(results);
    return 0;
}
