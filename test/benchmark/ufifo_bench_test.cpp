#include "ufifo_bench.hpp"

#include <atomic>
#include <chrono>
#include <thread>

#include <gtest/gtest.h>

namespace {

BenchResult MakeSample(double operations_per_second)
{
    return { "sample", 4, 1000, 1.0, operations_per_second, 1.0, 1.0 };
}

} // namespace

TEST(UfifoBenchTest, SummaryUsesMedianAndReportsSpread)
{
    const std::vector<BenchResult> samples = {
        MakeSample(80.0), MakeSample(100.0), MakeSample(90.0), MakeSample(120.0), MakeSample(110.0)
    };

    const BenchResult summary = SummarizeBenchResults(samples);

    EXPECT_DOUBLE_EQ(100.0, summary.ops_per_sec);
    EXPECT_EQ(5, summary.sample_count);
    EXPECT_DOUBLE_EQ(40.0, summary.spread_pct);
}

TEST(UfifoBenchTest, StartGateReleasesOnlyAfterWorkersAreReady)
{
    BenchStartGate gate;
    std::atomic<bool> released{ false };
    std::thread worker([&]() {
        gate.WorkerReadyAndWait();
        released.store(true);
    });

    const bool ready = gate.WaitUntilReady(1, std::chrono::seconds(1));
    EXPECT_TRUE(ready);
    EXPECT_FALSE(released.load());
    gate.Start();
    worker.join();
    EXPECT_TRUE(released.load());
}

TEST(UfifoBenchTest, StartGateReportsMissingWorker)
{
    BenchStartGate gate;

    EXPECT_FALSE(gate.WaitUntilReady(1, std::chrono::milliseconds(1)));
    gate.Start();
}
