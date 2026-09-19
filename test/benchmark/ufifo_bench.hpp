#pragma once

#include <string>
#include <thread>
#include <vector>

extern "C" {
#include "ufifo.h"
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

extern bool g_json_output;
extern bool g_pin_threads;

void InitializeAffinity();
void PinCurrentThread(int logical_index);
void PinThread(std::thread &thread, int logical_index);
const std::vector<int> &AvailableCpus();

void PrintResult(const BenchResult &result);
void PrintHeader();
void PrintJson(const std::vector<BenchResult> &results);

BenchResult RunPingPongBenchmark(int data_size, ufifo_lock_e lock, int iterations);
BenchResult RunSpscBenchmark(int data_size, ufifo_lock_e lock, int total_items);
BenchResult RunBurstBenchmark(int data_size, ufifo_lock_e lock, int rounds);
BenchResult RunMpscBenchmark(int data_size, int producer_count, int items_per_producer);
BenchResult RunSharedSpscBenchmark(int data_size, int total_items);
