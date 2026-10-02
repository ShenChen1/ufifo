#include "ufifo_bench.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <utility>

namespace {

struct Options {
    int scale = 1;
    int repetitions = 5;
};

int ParsePositiveInt(const char *text, const char *option)
{
    char *end = nullptr;
    const long value = strtol(text, &end, 10);
    if (text[0] == '\0' || *end != '\0' || value < 1 || value > 1000) {
        fprintf(stderr, "ufifo_bench: invalid %s: %s\n", option, text);
        exit(EXIT_FAILURE);
    }
    return static_cast<int>(value);
}

Options ParseOptions(int argc, char **argv)
{
    Options options;
    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--json") == 0)
            g_json_output = true;
        else if (strcmp(argv[index], "--no-pin") == 0)
            g_pin_threads = false;
        else if (strncmp(argv[index], "--repetitions=", 14) == 0)
            options.repetitions = ParsePositiveInt(argv[index] + 14, "repetitions");
        else
            options.scale = ParsePositiveInt(argv[index], "scale");
    }
    if ((options.repetitions & 1) == 0) {
        fprintf(stderr, "ufifo_bench: repetitions must be odd\n");
        exit(EXIT_FAILURE);
    }
    return options;
}

void PrintSystemInfo(const Options &options)
{
    if (g_json_output)
        return;

    printf("\n=== ufifo Performance Benchmark (scale=%d, repetitions=%d) ===\n",
           options.scale,
           options.repetitions);
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
    results.push_back(std::move(result));
}

void RunPingPongSection(int scale, std::vector<BenchResult> &results)
{
    const int iterations = 500000 * scale;
    for (int size : { 4, 64, 256, 1024, 4096 })
        AddResult(results, RunPingPongBenchmark(size, UFIFO_LOCK_NONE, iterations));
    for (int size : { 4, 64, 256, 1024, 4096 })
        AddResult(results, RunPingPongBenchmark(size, UFIFO_LOCK_THREAD, iterations * 4));
}

void RunSpscSection(int scale, std::vector<BenchResult> &results)
{
    const int items = 500000 * scale;
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunSpscBenchmark(size, UFIFO_LOCK_NONE, items));
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunSpscBenchmark(size, UFIFO_LOCK_THREAD, items * 3));
}

void RunBurstSection(int scale, std::vector<BenchResult> &results)
{
    const int rounds = 2000 * scale;
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunBurstBenchmark(size, UFIFO_LOCK_NONE, rounds));
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunBurstBenchmark(size, UFIFO_LOCK_THREAD, rounds * 4));
}

void RunMpscSection(int scale, std::vector<BenchResult> &results)
{
    const int items_per_producer = 500000 * scale;
    for (int size : { 4, 64, 256 })
        AddResult(results, RunMpscBenchmark(size, 2, items_per_producer));
    for (int size : { 4, 64, 256 })
        AddResult(results, RunMpscBenchmark(size, 4, items_per_producer));
}

void RunSharedSpscSection(int scale, std::vector<BenchResult> &results)
{
    const int items = 500000 * scale;
    for (int size : { 4, 64, 256, 1024 })
        AddResult(results, RunSharedSpscBenchmark(size, items));
}

std::vector<BenchResult> RunSuite(int scale, bool reverse_order)
{
    std::vector<BenchResult> results;
    if (!reverse_order) {
        RunPingPongSection(scale, results);
        RunSpscSection(scale, results);
        RunBurstSection(scale, results);
        RunMpscSection(scale, results);
        RunSharedSpscSection(scale, results);
    } else {
        RunSharedSpscSection(scale, results);
        RunMpscSection(scale, results);
        RunBurstSection(scale, results);
        RunSpscSection(scale, results);
        RunPingPongSection(scale, results);
    }
    return results;
}

std::vector<BenchResult> RunRepeated(const Options &options)
{
    std::vector<std::string> result_order;
    std::map<std::string, std::vector<BenchResult>> samples;

    for (int repetition = 0; repetition < options.repetitions; repetition++) {
        if (!g_json_output)
            fprintf(stderr, "ufifo_bench: repetition %d/%d\n", repetition + 1, options.repetitions);
        std::vector<BenchResult> run = RunSuite(options.scale, (repetition & 1) != 0);
        for (BenchResult &result : run) {
            if (samples.find(result.name) == samples.end())
                result_order.push_back(result.name);
            samples[result.name].push_back(std::move(result));
        }
    }

    std::vector<BenchResult> summaries;
    for (const std::string &name : result_order)
        summaries.push_back(SummarizeBenchResults(samples[name]));
    return summaries;
}

void PrintSummary(const std::vector<BenchResult> &results)
{
    if (g_json_output) {
        PrintJson(results);
        return;
    }
    PrintHeader();
    for (const BenchResult &result : results)
        PrintResult(result);
    printf("\n=== Summary: %zu benchmarks completed ===\n\n", results.size());
    printf("Each result is the median; Spread is (maximum - minimum) / median.\n");
    printf("PingPong and Burst isolate single-thread cost; SPSC and MPSC include scheduler noise.\n");
    printf("SharedSPSC counts two API operations per item: one put and one get.\n\n");
}

} // namespace

int main(int argc, char **argv)
{
    const Options options = ParseOptions(argc, argv);
    if (g_pin_threads) {
        InitializeAffinity();
        const int affinity_error = PinCurrentThread(0);
        if (affinity_error != 0) {
            fprintf(stderr, "ufifo_bench: cannot pin main thread: %d\n", affinity_error);
            return EXIT_FAILURE;
        }
    }
    PrintSystemInfo(options);

    std::vector<BenchResult> results = RunRepeated(options);
    PrintSummary(results);
    return 0;
}
