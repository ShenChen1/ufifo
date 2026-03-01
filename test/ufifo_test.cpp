/**
 * @file ufifo_test.cpp
 * @brief Comprehensive GTest parameterized test cases for ufifo library
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <mutex>
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
        const bool is_shared = (adapter_->GetMode() == DataMode::SHARED);
        const int total_handles = num_producers + num_consumers;

        ASSERT_EQ(0, adapter_->Create(fifo_size, UFIFO_LOCK_THREAD, total_handles));

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
                    int ret = adapter_->PutValue(h, val, p);
                    if (ret == 0) {
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
            threads.emplace_back([&, c, handle_idx]() {
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
        ufifo_close(c1);
    if (c2)
        ufifo_close(c2);
    if (fifo)
        ufifo_destroy(fifo);
}

// Issue 1: Fast consumer's put overwrites slow consumer's unconsumed data
TEST_F(EdgeCaseTest, SharedModePutRespectsMinOut)
{
    std::string name = GenerateName("mpsc_minout");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    ufifo_t *h1 = nullptr;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &h1));

    ufifo_t *h2 = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &attach, &h2));

    // Step 1: H1 puts 120 bytes of 0xAA → in=120
    char buf_a[120];
    memset(buf_a, 0xAA, sizeof(buf_a));
    ASSERT_EQ(120u, ufifo_put(h1, buf_a, sizeof(buf_a)));

    // Step 2: H1 gets 120 bytes → H1.out=120, H2.out=0
    char out1[120] = {};
    ASSERT_EQ(120u, ufifo_get(h1, out1, sizeof(out1)));

    // Step 3: H1 tries to put 200 bytes
    // own_out unused  = 256 - (120-120) = 256 → WRONG (would pass)
    // min_out unused  = 256 - (120-0)   = 136 → CORRECT (200 > 136, fails)
    char buf_b[200];
    memset(buf_b, 0xBB, sizeof(buf_b));
    unsigned int ret = ufifo_put(h1, buf_b, sizeof(buf_b));
    EXPECT_EQ(0u, ret) << "Put 200B should fail: only 136B available (min_out=0)";

    // Step 4: A smaller put (within 136B limit) should succeed
    char buf_c[100];
    memset(buf_c, 0xCC, sizeof(buf_c));
    ret = ufifo_put(h1, buf_c, sizeof(buf_c));
    EXPECT_EQ(100u, ret) << "Put 100B should succeed: fits within 136B available";

    // Step 5: H2 reads original data — must NOT be corrupted
    char out2[120] = {};
    ASSERT_EQ(120u, ufifo_get(h2, out2, sizeof(out2)));
    EXPECT_EQ(0, memcmp(out2, buf_a, sizeof(buf_a))) << "H2's data must not be corrupted by H1's put";

    ufifo_close(h2);
    ufifo_destroy(h1);
}

// Issue 2: Unsigned overflow causes impossible put after repeated put+get cycles
TEST_F(EdgeCaseTest, SharedModeNoUnsignedOverflow)
{
    std::string name = GenerateName("mpsc_nooverflow");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    ufifo_t *h1 = nullptr;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &init, &h1));

    ufifo_t *h2 = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(const_cast<char *>(name.c_str()), &attach, &h2));

    // H1 repeatedly puts 128B then gets 128B. H2 never gets.
    // Without fix: in keeps growing, unsigned overflow allows infinite puts
    // With fix: total put capped at 256 (buffer_size - (in - min_out))
    char data[128];
    memset(data, 0xAB, sizeof(data));
    char tmp[128];

    unsigned int total_put = 0;
    for (int i = 0; i < 10; i++) {
        unsigned int ret = ufifo_put(h1, data, sizeof(data));
        if (ret == 0)
            break;
        total_put += ret;
        ufifo_get(h1, tmp, sizeof(tmp));
    }

    // With fix: total_put = 256 (two puts of 128, then blocked)
    // Without fix: total_put = 1280 (all 10 puts succeed)
    EXPECT_LE(total_put, 256u) << "Total put should not exceed buffer size relative to slowest consumer";

    // H2 should be able to read all data that was put
    unsigned int total_got = 0;
    while (total_got < total_put) {
        unsigned int ret = ufifo_get(h2, tmp, sizeof(tmp));
        if (ret == 0)
            break;
        total_got += ret;
    }
    EXPECT_EQ(total_put, total_got) << "H2 should read exactly the amount of data that was put";

    ufifo_close(h2);
    ufifo_destroy(h1);
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}