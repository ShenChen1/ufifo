/**
 * @file ufifo_test.cpp
 * @brief Comprehensive GTest parameterized test cases for ufifo library
 */

#include <atomic>
#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "ufifo_test_adapter.hpp"

// Generate unique FIFO name
std::string GenerateName(const char *prefix)
{
    static std::atomic<int> counter{ 0 };
    return std::string(prefix) + "_" + std::to_string(counter++) + "_" + std::to_string(getpid());
}

// All Combinations
const TestParam ALL_COMBINATIONS[] = {
    { DataFormat::BYTESTREAM, DataMode::SOLE }, { DataFormat::RECORD, DataMode::SOLE },
    { DataFormat::TAG, DataMode::SOLE },        { DataFormat::BYTESTREAM, DataMode::SHARED },
    { DataFormat::RECORD, DataMode::SHARED },   { DataFormat::TAG, DataMode::SHARED }
};

std::string PrintParam(const testing::TestParamInfo<TestParam> &info)
{
    static const std::map<DataFormat, std::string> format_map = { { DataFormat::BYTESTREAM, "Byte" },
                                                                  { DataFormat::RECORD, "Record" },
                                                                  { DataFormat::TAG, "Tag" } };
    static const std::map<DataMode, std::string> mode_map = { { DataMode::SOLE, "Sole" },
                                                              { DataMode::SHARED, "Shared" } };

    std::string format_str = format_map.count(info.param.format) ? format_map.at(info.param.format) : "Unknown";
    std::string mode_str = mode_map.count(info.param.mode) ? mode_map.at(info.param.mode) : "Unknown";

    return format_str + "_" + mode_str;
}

// =============================================================================
// 1. Defensively testing API with bad attributes
// =============================================================================
class UfifoApiTest : public ::testing::Test {};

TEST_F(UfifoApiTest, OpenWithNullName)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(nullptr, &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithNullInit)
{
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>("test"), nullptr, &fifo));
}

TEST_F(UfifoApiTest, OpenWithInvalidOpt)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_MAX;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name = GenerateName("invalid_opt");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithInvalidLock)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_MAX;
    init.alloc.max_users = 1;
    std::string name = GenerateName("invalid_lock");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithZeroSize)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 0;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name = GenerateName("zero_size");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithNullHandle)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name = GenerateName("null_handle");
    EXPECT_NE(0, ufifo_open(const_cast<char *>(name.c_str()), &init, nullptr));
}

TEST_F(UfifoApiTest, OpenWithEmptyName)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>(""), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithInvalidDataMode)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.data_mode = UFIFO_DATA_MAX;
    init.alloc.max_users = 1;
    std::string name = GenerateName("invalid_mode");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithZeroMaxUsers)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 0;
    std::string name = GenerateName("zero_users");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));
}

TEST_F(UfifoApiTest, AttachNonExistent)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ATTACH;
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>("nonexistent_fifo_xyz"), &init, &fifo));
}

// =============================================================================
// 2. Base test suite class handling Parametrization
// =============================================================================
class ParameterizedTestBase : public ::testing::TestWithParam<TestParam> {
  protected:
    std::unique_ptr<UfifoTestAdapter> adapter_;
    std::string name_;

    void SetUp() override
    {
        const auto param = GetParam();
        name_ = GenerateName("ut");
        adapter_ = std::make_unique<UfifoTestAdapter>(param.format, param.mode, name_);
    }

    // Unified multi-thread topology runner for SPSC / SPMC / MPSC / MPMC
    void RunTopology(int num_producers, int num_consumers, int msgs_per_producer, int fifo_size)
    {
        ASSERT_EQ(0, adapter_->Create(fifo_size, UFIFO_LOCK_THREAD));

        int num_users = std::max(num_producers, num_consumers);
        for (int i = 0; i < num_users; ++i) {
            ufifo_t *h = nullptr;
            ASSERT_EQ(0, adapter_->Attach(&h));
        }

        const int total_msgs = msgs_per_producer * num_producers;

        // Barrier for synchronized start
        std::atomic<int> ready_count{ 0 };
        std::atomic<bool> start_flag{ false };
        const int total_threads = num_producers + num_consumers;

        std::atomic<int> sole_consumed{ 0 };
        std::vector<std::thread> threads;

        // Launch producers
        for (int p = 0; p < num_producers; ++p) {
            threads.emplace_back([&, p]() {
                ready_count.fetch_add(1, std::memory_order_release);
                while (!start_flag.load(std::memory_order_acquire))
                    std::this_thread::yield();

                for (int i = 0; i < msgs_per_producer; ++i) {
                    const int val = p * 100000 + i;
                    adapter_->PutValue(adapter_->GetHandle(p), val, p, -1);
                }
            });
        }

        // Launch consumers
        for (int c = 0; c < num_consumers; ++c) {
            threads.emplace_back([&, c]() {
                ready_count.fetch_add(1, std::memory_order_release);
                while (!start_flag.load(std::memory_order_acquire))
                    std::this_thread::yield();

                int count = 0;
                while (true) {
                    if (adapter_->GetMode() == DataMode::SHARED && count >= total_msgs)
                        break;
                    if (adapter_->GetMode() == DataMode::SOLE
                        && sole_consumed.load(std::memory_order_relaxed) >= total_msgs)
                        break;

                    int out = 0;
                    if (adapter_->GetValue(adapter_->GetHandle(c), out, 10) > 0) {
                        ++count;
                        if (adapter_->GetMode() == DataMode::SOLE)
                            sole_consumed.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                if (adapter_->GetMode() == DataMode::SHARED) {
                    EXPECT_EQ(total_msgs, count);
                }
            });
        }

        // Wait for all threads ready, then fire
        while (ready_count.load(std::memory_order_acquire) < total_threads)
            std::this_thread::yield();
        start_flag.store(true, std::memory_order_release);

        for (auto &t : threads)
            t.join();

        if (adapter_->GetMode() == DataMode::SOLE) {
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
    adapter_->PutValue(adapter_->GetMainHandle(), 1);
    adapter_->PutValue(adapter_->GetMainHandle(), 2);
    adapter_->Skip(adapter_->GetMainHandle());

    int out = 0;
    adapter_->GetValue(adapter_->GetMainHandle(), out);
    EXPECT_EQ(2, out);
}

TEST_P(SingletonTest, FifoFullEmpty)
{
    ASSERT_EQ(0, adapter_->Create(128));
    // Empty grab
    int out;
    EXPECT_EQ(0, adapter_->GetValue(adapter_->GetMainHandle(), out));

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
    EXPECT_GT(ufifo_size(adapter_->GetMainHandle()), 0u);
    EXPECT_EQ(0u, ufifo_len(adapter_->GetMainHandle()));

    adapter_->PutValue(adapter_->GetMainHandle(), 1);
    EXPECT_GT(ufifo_len(adapter_->GetMainHandle()), 0u);

    ufifo_reset(adapter_->GetMainHandle());
    EXPECT_EQ(0u, ufifo_len(adapter_->GetMainHandle()));
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
class TagSpecificTest : public ::testing::Test {
  protected:
    ufifo_t *fifo_ = nullptr;
    std::string name_;

    void SetUp() override
    {
        name_ = GenerateName("tag_spec");
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = 2048;
        init.alloc.force = 1;
        init.alloc.data_mode = UFIFO_DATA_SOLE;
        init.alloc.lock = UFIFO_LOCK_NONE;
        init.alloc.max_users = 1;
        init.hook.recsize = tagged_recsize;
        init.hook.rectag = tagged_rectag;

        ufifo_open(const_cast<char *>(name_.c_str()), &init, &fifo_);
    }

    void TearDown() override
    {
        if (fifo_)
            ufifo_destroy(fifo_);
    }

    void PutRec(int tag, const std::string &data)
    {
        char buf[256];
        TaggedRecord *rec = reinterpret_cast<TaggedRecord *>(buf);
        rec->size = data.size() + 1;
        rec->tag = tag;
        memcpy(rec->data, data.c_str(), rec->size);
        ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size);
    }
};

TEST_F(TagSpecificTest, OldestByTag)
{
    PutRec(1, "first_1");
    PutRec(2, "first_2");
    PutRec(1, "second_1");
    PutRec(2, "second_2");

    ufifo_oldest(fifo_, 2); // seek to oldest with tag=2
    char out_buf[128] = {};
    TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
    ufifo_get(fifo_, out, sizeof(out_buf));
    EXPECT_EQ(2u, out->tag);
    EXPECT_EQ(0, memcmp(out->data, "first_2", 7));
}

TEST_F(TagSpecificTest, NewestByTag)
{
    PutRec(1, "first_1");
    PutRec(2, "first_2");
    PutRec(1, "second_1");

    ufifo_newest(fifo_, 1); // seek to newest with tag=1
    char out_buf[128] = {};
    TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
    ufifo_get(fifo_, out, sizeof(out_buf));
    EXPECT_EQ(1u, out->tag);
    EXPECT_EQ(0, memcmp(out->data, "second_1", 8));
}

TEST_F(TagSpecificTest, TagNotFound)
{
    PutRec(1, "data");
    ufifo_oldest(fifo_, 999); // non-existent tag
    char out_buf[128] = {};
    unsigned int ret = ufifo_get(fifo_, out_buf, sizeof(out_buf));
    (void)ret; // shouldn't crash
}

TEST_F(TagSpecificTest, MultiTagMixed)
{
    for (int i = 0; i < 10; i++) {
        char content[16];
        snprintf(content, sizeof(content), "tag%d_%d", i % 3, i);
        PutRec(i % 3, content);
    }

    int count = 0;
    while (ufifo_len(fifo_)) {
        ufifo_oldest(fifo_, 0);
        char out_buf[128] = {};
        TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
        if (ufifo_get(fifo_, out, sizeof(out_buf)) == 0)
            break;
        if (out->tag == 0)
            count++;
        else
            break;
    }
    EXPECT_GT(count, 0);
}

// =============================================================================
// 9. Edge Cases
// =============================================================================
class EdgeCaseTest : public ::testing::Test {};

TEST_F(EdgeCaseTest, AllocForceOverwrite)
{
    std::string name = GenerateName("ec_force");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));
    int val = 99;
    ufifo_put(fifo, &val, sizeof(val));
    ufifo_destroy(fifo);

    init.alloc.size = 128; // Force overwrite with different parameters
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));
    EXPECT_EQ(0u, ufifo_len(fifo));
    ufifo_destroy(fifo);
}

TEST_F(EdgeCaseTest, ProcessLockCrashRecovery)
{
    std::string name = GenerateName("ec_crash");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));

    pid_t pid = fork();
    if (pid == 0) {
        int val = 999;
        ufifo_put(fifo, &val, sizeof(val));
        _exit(0); // Exit abandoning the lock/handle mapping
    } else {
        ASSERT_GT(pid, 0);
        int status;
        waitpid(pid, &status, 0);

        int out = 0;
        unsigned int ret = ufifo_get(fifo, &out, sizeof(out));
        if (ret > 0) {
            EXPECT_EQ(999, out);
        }
    }
    ufifo_destroy(fifo);
}

TEST_F(EdgeCaseTest, SharedModeUserLimit)
{
    std::string name = GenerateName("ec_usrlmt");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &fifo));

    ufifo_t *c1 = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &attach, &c1));

    ufifo_t *c2 = nullptr;
    EXPECT_NE(0, ufifo_open(const_cast<char *>(name.c_str()), &attach, &c2));

    if (c1)
        ufifo_destroy(c1);
    if (c2)
        ufifo_destroy(c2);
    if (fifo)
        ufifo_destroy(fifo);
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}