#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include "ufifo.h"
}

struct BenchResult {
    std::string name;
    int data_size = 0;
    long long total_ops = 0;
    double elapsed_sec = 0.0;
    double ops_per_sec = 0.0;
    double mb_per_sec = 0.0;
    double avg_ns = 0.0;
    int sample_count = 1;
    double spread_pct = 0.0;
};

class BenchStartGate {
  public:
    void WorkerReadyAndWait();
    bool WaitUntilReady(size_t expected, std::chrono::milliseconds timeout);
    void Start();

  private:
    std::mutex mutex_;
    std::condition_variable condition_;
    size_t ready_count_ = 0;
    bool started_ = false;
};

extern bool g_json_output;
extern bool g_pin_threads;

void InitializeAffinity();
int PinCurrentThread(int logical_index);
const std::vector<int> &AvailableCpus();

BenchResult SummarizeBenchResults(const std::vector<BenchResult> &samples);
void PrintResult(const BenchResult &result);
void PrintHeader();
void PrintJson(const std::vector<BenchResult> &results);

BenchResult RunPingPongBenchmark(int data_size, ufifo_lock_e lock, int iterations);
BenchResult RunSpscBenchmark(int data_size, ufifo_lock_e lock, int total_items);
BenchResult RunBurstBenchmark(int data_size, ufifo_lock_e lock, int rounds);
BenchResult RunMpscBenchmark(int data_size, int producer_count, int items_per_producer);
BenchResult RunSharedSpscBenchmark(int data_size, int total_items);
