#include "ufifo_test_support.hpp"

namespace {

class StartGate {
  public:
    explicit StartGate(int participant_count) : participant_count_(participant_count) {}

    void ArriveAndWait()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_count_++;
        ready_.notify_one();
        start_.wait(lock, [&] { return started_; });
    }

    void Release()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait(lock, [&] { return ready_count_ == participant_count_; });
        started_ = true;
        lock.unlock();
        start_.notify_all();
    }

  private:
    const int participant_count_;
    int ready_count_ = 0;
    bool started_ = false;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::condition_variable start_;
};

struct TopologyRun {
    TopologyRun(int producer_count, int consumer_count, int messages_per_producer, bool shared)
        : producer_count(producer_count),
          consumer_count(consumer_count),
          messages_per_producer(messages_per_producer),
          total_messages(producer_count * messages_per_producer),
          shared(shared),
          gate(producer_count + consumer_count)
    {}

    int producer_count;
    int consumer_count;
    int messages_per_producer;
    int total_messages;
    bool shared;
    StartGate gate;
    std::atomic<int> sole_consumed{ 0 };
    std::vector<std::thread> threads;
};

} // namespace

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

    void AddProducer(TopologyRun &run, int producer_index)
    {
        run.threads.emplace_back([&, producer_index]() {
            run.gate.ArriveAndWait();
            ufifo_t *handle = adapter_->GetHandle(producer_index);
            for (int count = 0; count < run.messages_per_producer;) {
                const int value = producer_index * 100000 + count;
                if (adapter_->PutValue(handle, value, producer_index) > 0) {
                    count++;
                } else if (run.shared) {
                    int discarded = 0;
                    adapter_->GetValue(handle, discarded);
                } else {
                    std::this_thread::yield();
                }
            }
            if (run.shared)
                adapter_->Detach(handle);
        });
    }

    void AddConsumer(TopologyRun &run, int handle_index)
    {
        run.threads.emplace_back([&, handle_index]() {
            run.gate.ArriveAndWait();
            int count = 0;
            ufifo_t *handle = adapter_->GetHandle(handle_index);
            while ((run.shared && count < run.total_messages)
                   || (!run.shared && run.sole_consumed.load(std::memory_order_relaxed) < run.total_messages)) {
                int value = 0;
                if (adapter_->GetValue(handle, value, 10) > 0) {
                    count++;
                    if (!run.shared)
                        run.sole_consumed.fetch_add(1, std::memory_order_relaxed);
                }
            }
            if (run.shared) {
                EXPECT_EQ(run.total_messages, count);
            }
        });
    }

    void RunTopology(int producer_count, int consumer_count, int messages_per_producer, int fifo_size)
    {
        const bool shared = adapter_->GetMode() == DataMode::SHARED;
        if (GetParam().lock == UFIFO_LOCK_NONE && producer_count > 1)
            GTEST_SKIP() << "UFIFO_LOCK_NONE does not support multiple producers";
        if (GetParam().lock == UFIFO_LOCK_NONE && consumer_count > 1 && !shared)
            GTEST_SKIP() << "UFIFO_LOCK_NONE does not support multiple consumers in SOLE mode";

        const int handle_count = producer_count + consumer_count;
        ASSERT_EQ(0, adapter_->Create(fifo_size, handle_count));
        for (int index = 1; index < handle_count; index++) {
            ufifo_t *handle = nullptr;
            ASSERT_EQ(0, adapter_->Attach(&handle));
        }

        TopologyRun run(producer_count, consumer_count, messages_per_producer, shared);
        for (int producer = 0; producer < producer_count; producer++)
            AddProducer(run, producer);
        for (int consumer = 0; consumer < consumer_count; consumer++)
            AddConsumer(run, producer_count + consumer);
        run.gate.Release();
        for (auto &thread : run.threads)
            thread.join();
        if (!shared) {
            EXPECT_EQ(run.total_messages, run.sole_consumed.load(std::memory_order_relaxed));
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

TEST_P(SingletonTest, UsesConfiguredLock)
{
    ASSERT_EQ(0, adapter_->Create(512));
    ASSERT_NE(nullptr, adapter_->GetMainHandle());
    EXPECT_EQ(GetParam().lock, adapter_->GetMainHandle()->lock_type);
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
