#include <algorithm>

#include "ufifo_test_support.hpp"

namespace {

struct TopologyRun {
    TopologyRun(int producer_count, int consumer_count, int messages_per_producer, bool shared)
        : producer_count(producer_count),
          consumer_count(consumer_count),
          messages_per_producer(messages_per_producer),
          total_messages(producer_count * messages_per_producer),
          shared(shared),
          gate(producer_count + consumer_count),
          deadline(std::chrono::seconds(30)),
          received(consumer_count)
    {}

    void Fail(int failure)
    {
        first_failure.Record(failure);
    }

    bool ShouldStop()
    {
        if (!first_failure.Ok())
            return true;
        if (!deadline.Expired())
            return false;
        Fail(-ETIMEDOUT);
        return true;
    }

    int producer_count;
    int consumer_count;
    int messages_per_producer;
    int total_messages;
    bool shared;
    StartGate gate;
    TestDeadline deadline;
    std::atomic<int> sole_consumed{ 0 };
    FirstFailure first_failure;
    std::vector<std::vector<int>> received;
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
            if (!run.gate.ArriveAndWait(run.deadline)) {
                run.Fail(-ETIMEDOUT);
                return;
            }
            ufifo_t *handle = adapter_->GetHandle(producer_index);
            if (!handle) {
                run.Fail(-EINVAL);
                return;
            }
            for (int count = 0; count < run.messages_per_producer && !run.ShouldStop();) {
                const int value = producer_index * 100000 + count;
                ssize_t ret = adapter_->PutValue(handle, value, producer_index);
                if (ret > 0) {
                    count++;
                } else if (ret == -EAGAIN) {
                    std::this_thread::yield();
                } else {
                    run.Fail(ret < 0 ? static_cast<int>(ret) : -EIO);
                }
            }
        });
    }

    void AddConsumer(TopologyRun &run, int handle_index)
    {
        run.threads.emplace_back([&, handle_index]() {
            if (!run.gate.ArriveAndWait(run.deadline)) {
                run.Fail(-ETIMEDOUT);
                return;
            }
            int count = 0;
            ufifo_t *handle = adapter_->GetHandle(handle_index);
            if (!handle) {
                run.Fail(-EINVAL);
                return;
            }
            std::vector<int> &values = run.received[handle_index - run.producer_count];
            values.reserve(run.total_messages);
            while ((run.shared && count < run.total_messages)
                   || (!run.shared && run.sole_consumed.load(std::memory_order_relaxed) < run.total_messages)) {
                if (run.ShouldStop())
                    break;
                int value = 0;
                ssize_t ret = adapter_->GetValue(handle, value, 10);
                if (ret > 0) {
                    values.push_back(value);
                    count++;
                    if (!run.shared)
                        run.sole_consumed.fetch_add(1, std::memory_order_relaxed);
                } else if (ret != -EAGAIN && ret != -ETIMEDOUT) {
                    run.Fail(ret < 0 ? static_cast<int>(ret) : -EIO);
                }
            }
        });
    }

    std::vector<int> ExpectedValues(const TopologyRun &run)
    {
        std::vector<int> expected;
        expected.reserve(run.total_messages);
        for (int producer = 0; producer < run.producer_count; producer++) {
            for (int count = 0; count < run.messages_per_producer; count++)
                expected.push_back(producer * 100000 + count);
        }
        return expected;
    }

    void ExpectProducerOrder(const TopologyRun &run, const std::vector<int> &values)
    {
        std::vector<int> next_count(run.producer_count, 0);
        for (int value : values) {
            const int producer = value / 100000;
            const int count = value % 100000;
            if (producer < 0 || producer >= run.producer_count) {
                ADD_FAILURE() << "Invalid producer id in value " << value;
                continue;
            }
            EXPECT_EQ(next_count[producer], count) << "Out-of-order value from producer " << producer;
            next_count[producer]++;
        }
        for (int count : next_count)
            EXPECT_EQ(run.messages_per_producer, count);
    }

    void ExpectExactValues(const std::vector<int> &expected, std::vector<int> actual)
    {
        std::sort(actual.begin(), actual.end());
        EXPECT_EQ(expected, actual);
    }

    void RunTopology(int producer_count, int consumer_count, int messages_per_producer, int fifo_size)
    {
        const bool shared = adapter_->GetMode() == DataMode::SHARED;
        if (GetParam().lock == UFIFO_LOCK_NONE && producer_count > 1)
            GTEST_SKIP() << "UFIFO_LOCK_NONE does not support multiple producers";
        if (GetParam().lock == UFIFO_LOCK_NONE && consumer_count > 1 && !shared)
            GTEST_SKIP() << "UFIFO_LOCK_NONE does not support multiple consumers in SOLE mode";

        const int handle_count = producer_count + consumer_count;
        const ufifo_role_e creator_role = (producer_count > 0) ? UFIFO_ROLE_PRODUCER : UFIFO_ROLE_CONSUMER;
        ASSERT_EQ(0, adapter_->Create(fifo_size, handle_count, creator_role));
        for (int index = 1; index < handle_count; index++) {
            ufifo_t *handle = nullptr;
            const ufifo_role_e role = (index < producer_count) ? UFIFO_ROLE_PRODUCER : UFIFO_ROLE_CONSUMER;
            ASSERT_EQ(0, adapter_->Attach(&handle, role));
        }

        TopologyRun run(producer_count, consumer_count, messages_per_producer, shared);
        for (int producer = 0; producer < producer_count; producer++)
            AddProducer(run, producer);
        for (int consumer = 0; consumer < consumer_count; consumer++)
            AddConsumer(run, producer_count + consumer);
        if (!run.gate.Release(run.deadline))
            run.Fail(-ETIMEDOUT);
        for (auto &thread : run.threads)
            thread.join();

        ASSERT_EQ(0, run.first_failure.Get());
        const std::vector<int> expected = ExpectedValues(run);
        if (shared) {
            for (const auto &values : run.received) {
                EXPECT_EQ(run.total_messages, static_cast<int>(values.size()));
                ExpectExactValues(expected, values);
                ExpectProducerOrder(run, values);
            }
        } else {
            std::vector<int> all_values;
            all_values.reserve(run.total_messages);
            for (const auto &values : run.received)
                all_values.insert(all_values.end(), values.begin(), values.end());
            EXPECT_EQ(run.total_messages, run.sole_consumed.load(std::memory_order_relaxed));
            ExpectExactValues(expected, std::move(all_values));
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
