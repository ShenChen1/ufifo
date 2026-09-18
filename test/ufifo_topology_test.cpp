#include "ufifo_test_support.hpp"

class ParameterizedTestBase : public ::testing::TestWithParam<TestParam> {
  protected:
    std::unique_ptr<UfifoTestAdapter> adapter_;
    std::string name_;

    void SetUp() override
    {
        const auto param = GetParam();
        name_ = GenerateName("ut");
        adapter_ = std::make_unique<UfifoTestAdapter>(param.format, param.mode, param.lock, name_);
    }

    // Unified multi-thread topology runner for SPSC / SPMC / MPSC / MPMC
    void RunTopology(int num_producers, int num_consumers, int msgs_per_producer, int fifo_size)
    {
        const auto param = GetParam();
        const bool is_shared = (adapter_->GetMode() == DataMode::SHARED);

        if (param.lock == UFIFO_LOCK_NONE) {
            if (num_producers > 1) {
                GTEST_SKIP() << "UFIFO_LOCK_NONE does not support multiple producers";
            }
            if (num_consumers > 1 && !is_shared) {
                GTEST_SKIP() << "UFIFO_LOCK_NONE does not support multiple consumers in SOLE mode";
            }
        }

        /*
         * In SHARED mode, every registered handle is an independent consumer
         * whose `out` pointer must advance, otherwise __ufifo_min_out will
         * block all puts.
         *
         * Handle allocation:
         *   handles_[0]                     = Create  (producer 0)
         *   handles_[1 .. num_producers-1]  = Attach  (producer 1..N-1)
         *   handles_[num_producers .. N-1]  = Attach  (consumer 0..M-1)
         *
         * Total users = num_producers + num_consumers.
         * In SHARED mode, producers call get after put to advance their out.
         */
        const int total_handles = num_producers + num_consumers;

        ASSERT_EQ(0, adapter_->Create(fifo_size, adapter_->GetLock(), total_handles));

        for (int i = 1; i < total_handles; ++i) {
            ufifo_t *h = nullptr;
            ASSERT_EQ(0, adapter_->Attach(&h));
        }

        const int total_msgs = msgs_per_producer * num_producers;

        // Barrier for synchronized start
        std::mutex start_mtx;
        std::condition_variable start_cv;
        int ready_count = 0;
        bool start_flag = false;
        const int total_threads = num_producers + num_consumers;

        std::atomic<int> sole_consumed{ 0 };
        std::vector<std::thread> threads;

        // Launch producers — each uses handles_[p]
        for (int p = 0; p < num_producers; ++p) {
            threads.emplace_back([&, p]() {
                {
                    std::unique_lock<std::mutex> lck(start_mtx);
                    ready_count++;
                    if (ready_count == total_threads)
                        start_cv.notify_all();
                    start_cv.wait(lck, [&] { return start_flag; });
                }

                int count = 0;
                ufifo_t *h = adapter_->GetHandle(p);
                while (count < msgs_per_producer) {
                    const int val = p * 100000 + count;
                    ssize_t ret = adapter_->PutValue(h, val, p);
                    if (ret <= 0) {
                        if (is_shared) {
                            std::this_thread::yield();
                            int out = 0;
                            adapter_->GetValue(h, out);
                        }
                        continue;
                    }
                    count++;
                }

                if (is_shared) {
                    adapter_->Detach(h);
                }
            });
        }

        // Launch consumers — each uses handles_[num_producers + c]
        for (int c = 0; c < num_consumers; ++c) {
            const int handle_idx = num_producers + c;
            threads.emplace_back([&, handle_idx]() {
                {
                    std::unique_lock<std::mutex> lck(start_mtx);
                    ready_count++;
                    if (ready_count == total_threads)
                        start_cv.notify_all();
                    start_cv.wait(lck, [&] { return start_flag; });
                }

                int count = 0;
                ufifo_t *h = adapter_->GetHandle(handle_idx);
                while (true) {
                    if (is_shared && count >= total_msgs)
                        break;
                    if (!is_shared && sole_consumed.load(std::memory_order_relaxed) >= total_msgs)
                        break;

                    int out = 0;
                    if (adapter_->GetValue(h, out, 10) > 0) {
                        ++count;
                        if (!is_shared)
                            sole_consumed.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                if (is_shared) {
                    EXPECT_EQ(total_msgs, count);
                }
            });
        }

        // Wait for all threads ready, then fire
        {
            std::unique_lock<std::mutex> lck(start_mtx);
            start_cv.wait(lck, [&] { return ready_count == total_threads; });
            start_flag = true;
        }
        start_cv.notify_all();

        for (auto &t : threads)
            t.join();

        if (!is_shared) {
            EXPECT_EQ(total_msgs, sole_consumed.load(std::memory_order_relaxed));
        }
    }
};

class SingletonTest : public ParameterizedTestBase {};
class SpscTest : public ParameterizedTestBase {};
class SpmcTest : public ParameterizedTestBase {};
class MpscTest : public ParameterizedTestBase {};
class MpmcTest : public ParameterizedTestBase {};

// =============================================================================
// 3. Singleton Tests
// =============================================================================
TEST_P(SingletonTest, OpenClose)
{
    ASSERT_EQ(0, adapter_->Create(512));
    EXPECT_NE(nullptr, adapter_->GetMainHandle());
}

TEST_P(SingletonTest, BasicPutGet)
{
    ASSERT_EQ(0, adapter_->Create(512));
    EXPECT_GT(adapter_->PutValue(adapter_->GetMainHandle(), 42), 0);
    int out = 0;
    EXPECT_GT(adapter_->GetValue(adapter_->GetMainHandle(), out), 0);
    EXPECT_EQ(42, out);
}

TEST_P(SingletonTest, SkipOperation)
{
    ASSERT_EQ(0, adapter_->Create(512));
    ssize_t first_size = adapter_->PutValue(adapter_->GetMainHandle(), 1);
    ASSERT_GT(first_size, 0);
    adapter_->PutValue(adapter_->GetMainHandle(), 2);
    EXPECT_EQ(first_size, adapter_->Skip(adapter_->GetMainHandle()));

    int out = 0;
    adapter_->GetValue(adapter_->GetMainHandle(), out);
    EXPECT_EQ(2, out);
}

TEST_P(SingletonTest, FifoFullEmpty)
{
    ASSERT_EQ(0, adapter_->Create(128));
    // Empty grab
    int out;
    EXPECT_EQ(-EAGAIN, adapter_->GetValue(adapter_->GetMainHandle(), out));

    int count = 0;
    while (adapter_->PutValue(adapter_->GetMainHandle(), ++count) > 0) {
    }
    EXPECT_GT(count, 0); // Must have written at least 1
}

TEST_P(SingletonTest, PeekLen)
{
    ASSERT_EQ(0, adapter_->Create(512));
    adapter_->PutValue(adapter_->GetMainHandle(), 99);
    EXPECT_GT(adapter_->PeekLen(adapter_->GetMainHandle()), 0);
    int out = 0;
    adapter_->GetValue(adapter_->GetMainHandle(), out); // consume to clear
    EXPECT_EQ(99, out);
}

TEST_P(SingletonTest, SizeAndLenAndReset)
{
    ASSERT_EQ(0, adapter_->Create(256));
    EXPECT_GT(ufifo_size(adapter_->GetMainHandle()), 0);
    EXPECT_EQ(0, ufifo_len(adapter_->GetMainHandle()));

    adapter_->PutValue(adapter_->GetMainHandle(), 1);
    EXPECT_GT(ufifo_len(adapter_->GetMainHandle()), 0);

    EXPECT_EQ(0, ufifo_reset(adapter_->GetMainHandle()));
    EXPECT_EQ(0, ufifo_len(adapter_->GetMainHandle()));
}

TEST_P(SingletonTest, LargeDataThroughput)
{
    ASSERT_EQ(0, adapter_->Create(4096));
    for (int i = 0; i < 500; i++) {
        adapter_->PutValue(adapter_->GetMainHandle(), i);
        int out = -1;
        adapter_->GetValue(adapter_->GetMainHandle(), out);
        EXPECT_EQ(i, out);
    }
}

INSTANTIATE_TEST_SUITE_P(UfifoTests, SingletonTest, testing::ValuesIn(ALL_COMBINATIONS), PrintParam);

// =============================================================================
// 4. SPSC Tests
// =============================================================================
TEST_P(SpscTest, Basic)
{
    RunTopology(1, 1, 1000, 4096);
}

TEST_P(SpscTest, Boundary)
{
    RunTopology(1, 1, 200, 128);
}

TEST_P(SpscTest, Stress)
{
    RunTopology(1, 1, 30000, 4096);
}

INSTANTIATE_TEST_SUITE_P(UfifoTests, SpscTest, testing::ValuesIn(ALL_COMBINATIONS), PrintParam);

// =============================================================================
// 5. SPMC Tests
// =============================================================================
TEST_P(SpmcTest, Basic)
{
    RunTopology(1, 3, 1000, 4096);
}
TEST_P(SpmcTest, Boundary)
{
    RunTopology(1, 3, 200, 128);
}
TEST_P(SpmcTest, Stress)
{
    RunTopology(1, 3, 30000, 4096);
}

INSTANTIATE_TEST_SUITE_P(UfifoTests, SpmcTest, testing::ValuesIn(ALL_COMBINATIONS), PrintParam);

// =============================================================================
// 6. MPSC Tests
// =============================================================================
TEST_P(MpscTest, Basic)
{
    RunTopology(3, 1, 1000, 4096);
}
TEST_P(MpscTest, Boundary)
{
    RunTopology(3, 1, 200, 128);
}
TEST_P(MpscTest, Stress)
{
    RunTopology(3, 1, 30000, 4096);
}

INSTANTIATE_TEST_SUITE_P(UfifoTests, MpscTest, testing::ValuesIn(ALL_COMBINATIONS), PrintParam);

// =============================================================================
// 7. MPMC Tests
// =============================================================================
TEST_P(MpmcTest, Basic)
{
    RunTopology(2, 2, 1000, 4096);
}
TEST_P(MpmcTest, Boundary)
{
    RunTopology(2, 2, 200, 128);
}
TEST_P(MpmcTest, Stress)
{
    RunTopology(2, 2, 30000, 4096);
}

INSTANTIATE_TEST_SUITE_P(UfifoTests, MpmcTest, testing::ValuesIn(ALL_COMBINATIONS), PrintParam);

// =============================================================================
// 8. Tag Specific Tests
// =============================================================================
