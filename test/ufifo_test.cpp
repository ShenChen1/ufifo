/**
 * @file ufifo_test.cpp
 * @brief Comprehensive GTest test cases for ufifo library
 *
 * Test matrix: DataFormat(Bytestream/Record/Tag) x DataMode(SOLE/SHARED) x Instance(Single/SPSC/SPMC/MPSC/MPMC)
 */

#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>

extern "C" {
#include "ufifo.h"
}

// =============================================================================
// Part 0: Fixtures & Helpers
// =============================================================================

// Record structure for Record/Tag mode tests (inline data, no callback needed)
struct TestRecord {
    unsigned int size;  // payload size
    char data[0];       // flexible array member
};

// Tagged record structure for Tag mode tests
struct TaggedRecord {
    unsigned int size;  // payload size
    unsigned int tag;
    char data[0];       // flexible array member
};

// recsize hook for Record mode
static unsigned int test_recsize(unsigned char* p1, unsigned int n1, unsigned char* p2) {
    unsigned int size = sizeof(TestRecord);
    if (n1 >= size) {
        TestRecord* rec = reinterpret_cast<TestRecord*>(p1);
        size = rec->size;
    } else {
        TestRecord rec;
        char* p = reinterpret_cast<char*>(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        size = rec.size;
    }
    return sizeof(TestRecord) + size;
}

// recsize hook for Tag mode
static unsigned int tagged_recsize(unsigned char* p1, unsigned int n1, unsigned char* p2) {
    unsigned int size = sizeof(TaggedRecord);
    if (n1 >= size) {
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(p1);
        size = rec->size;
    } else {
        TaggedRecord rec;
        char* p = reinterpret_cast<char*>(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        size = rec.size;
    }
    return sizeof(TaggedRecord) + size;
}

// rectag hook for Tag mode
static unsigned int tagged_rectag(unsigned char* p1, unsigned int n1, unsigned char* p2) {
    unsigned int tag = 0;
    unsigned int size = sizeof(TaggedRecord);
    if (n1 >= size) {
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(p1);
        tag = rec->tag;
    } else {
        TaggedRecord rec;
        char* p = reinterpret_cast<char*>(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        tag = rec.tag;
    }
    return tag;
}

/**
 * @brief Base fixture: single fifo handle with auto cleanup
 */
class UfifoTestBase : public ::testing::Test {
protected:
    ufifo_t* fifo_ = nullptr;
    std::string fifo_name_;

    void TearDown() override {
        if (fifo_) {
            ufifo_destroy(fifo_);
            fifo_ = nullptr;
        }
    }

    std::string GenerateName(const char* prefix) {
        static std::atomic<int> counter{0};
        fifo_name_ = std::string(prefix) + "_" + std::to_string(counter++) +
                     "_" + std::to_string(getpid());
        return fifo_name_;
    }
};

/**
 * @brief Bytestream fixture: creates a bytestream fifo
 */
class BytestreamFixture : public UfifoTestBase {
protected:
    int CreateFifo(unsigned int size,
                   ufifo_lock_e lock = UFIFO_LOCK_NONE,
                   ufifo_data_mode_e data_mode = UFIFO_DATA_SOLE,
                   unsigned int max_users = 1) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = lock;
        init.alloc.data_mode = data_mode;
        init.alloc.max_users = max_users;
        return ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_);
    }
};

/**
 * @brief Record fixture: creates a record-mode fifo with recsize hook
 */
class RecordFixture : public UfifoTestBase {
protected:
    int CreateFifo(unsigned int size,
                   ufifo_lock_e lock = UFIFO_LOCK_NONE,
                   ufifo_data_mode_e data_mode = UFIFO_DATA_SOLE,
                   unsigned int max_users = 1) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = lock;
        init.alloc.data_mode = data_mode;
        init.alloc.max_users = max_users;
        init.hook.recsize = test_recsize;
        return ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_);
    }
};

/**
 * @brief Tag fixture: creates a tag-mode fifo with recsize + rectag hooks
 */
class TagFixture : public UfifoTestBase {
protected:
    int CreateFifo(unsigned int size,
                   ufifo_lock_e lock = UFIFO_LOCK_NONE,
                   ufifo_data_mode_e data_mode = UFIFO_DATA_SOLE,
                   unsigned int max_users = 1) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = lock;
        init.alloc.data_mode = data_mode;
        init.alloc.max_users = max_users;
        init.hook.recsize = tagged_recsize;
        init.hook.rectag = tagged_rectag;
        return ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_);
    }

    void PutTaggedRecord(unsigned int tag, const char* content) {
        char buf[256];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = strlen(content) + 1;
        rec->tag = tag;
        memcpy(rec->data, content, rec->size);
        ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size);
    }
};

/**
 * @brief Multi-user fixture: manages multiple fifo handles
 */
class MultiUserFixture : public ::testing::Test {
protected:
    std::vector<ufifo_t*> fifos_;
    std::string fifo_name_;

    void TearDown() override {
        for (auto* f : fifos_) {
            if (f) ufifo_destroy(f);
        }
        fifos_.clear();
    }

    std::string GenerateName(const char* prefix) {
        static std::atomic<int> counter{0};
        fifo_name_ = std::string(prefix) + "_" + std::to_string(counter++) +
                     "_" + std::to_string(getpid());
        return fifo_name_;
    }

    // Attach a consumer to the existing fifo (SHARED mode)
    int AttachConsumer(ufifo_t** handle, ufifo_hook_t hook = {}) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ATTACH;
        init.hook = hook;
        return ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, handle);
    }
};

// =============================================================================
// Part 1: API Parameter Tests
// =============================================================================

class UfifoApiTest : public BytestreamFixture {};

TEST_F(UfifoApiTest, OpenWithNullName) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    EXPECT_NE(0, ufifo_open(nullptr, &init, &fifo_));
}

TEST_F(UfifoApiTest, OpenWithNullInit) {
    EXPECT_NE(0, ufifo_open(const_cast<char*>("test"), nullptr, &fifo_));
}

TEST_F(UfifoApiTest, OpenWithInvalidOpt) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_MAX;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    GenerateName("invalid_opt");
    EXPECT_NE(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));
}

TEST_F(UfifoApiTest, OpenWithInvalidLock) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_MAX;
    init.alloc.max_users = 1;
    GenerateName("invalid_lock");
    EXPECT_NE(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));
}

TEST_F(UfifoApiTest, OpenWithZeroSize) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 0;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    GenerateName("zero_size");
    EXPECT_NE(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));
}

TEST_F(UfifoApiTest, OpenWithNullHandle) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    GenerateName("null_handle");
    EXPECT_NE(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, nullptr));
}

TEST_F(UfifoApiTest, OpenWithEmptyName) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    EXPECT_NE(0, ufifo_open(const_cast<char*>(""), &init, &fifo_));
}

TEST_F(UfifoApiTest, OpenWithInvalidDataMode) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.data_mode = UFIFO_DATA_MAX;
    init.alloc.max_users = 1;
    GenerateName("invalid_mode");
    EXPECT_NE(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));
}

TEST_F(UfifoApiTest, OpenWithZeroMaxUsers) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 0;
    GenerateName("zero_users");
    EXPECT_NE(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));
}

TEST_F(UfifoApiTest, AttachNonExistent) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ATTACH;
    EXPECT_NE(0, ufifo_open(const_cast<char*>("nonexistent_fifo_xyz"), &init, &fifo_));
}

// =============================================================================
// Part 2: Bytestream + SOLE
// =============================================================================

// 2.1 Single instance
class ByteSoleSingle : public BytestreamFixture {};

TEST_F(ByteSoleSingle, OpenClose) {
    GenerateName("bs_open");
    ASSERT_EQ(0, CreateFifo(256));
    EXPECT_NE(nullptr, fifo_);
}

TEST_F(ByteSoleSingle, BasicPutGet) {
    GenerateName("bs_basic");
    ASSERT_EQ(0, CreateFifo(256));
    int val = 42;
    EXPECT_EQ(sizeof(val), ufifo_put(fifo_, &val, sizeof(val)));
    int out = 0;
    EXPECT_EQ(sizeof(out), ufifo_get(fifo_, &out, sizeof(out)));
    EXPECT_EQ(42, out);
}

TEST_F(ByteSoleSingle, PutGetMultiple) {
    GenerateName("bs_multi");
    ASSERT_EQ(0, CreateFifo(256));
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(sizeof(i), ufifo_put(fifo_, &i, sizeof(i)));
    }
    for (int i = 0; i < 10; i++) {
        int out = -1;
        EXPECT_EQ(sizeof(out), ufifo_get(fifo_, &out, sizeof(out)));
        EXPECT_EQ(i, out);
    }
}

TEST_F(ByteSoleSingle, PeekWithoutConsume) {
    GenerateName("bs_peek");
    ASSERT_EQ(0, CreateFifo(256));
    int val = 99;
    ufifo_put(fifo_, &val, sizeof(val));
    int peek_val = 0;
    EXPECT_EQ(sizeof(peek_val), ufifo_peek(fifo_, &peek_val, sizeof(peek_val)));
    EXPECT_EQ(99, peek_val);
    // data should still be there
    EXPECT_EQ(sizeof(int), ufifo_len(fifo_));
    int out = 0;
    EXPECT_EQ(sizeof(out), ufifo_get(fifo_, &out, sizeof(out)));
    EXPECT_EQ(99, out);
}

TEST_F(ByteSoleSingle, SkipOperation) {
    GenerateName("bs_skip");
    ASSERT_EQ(0, CreateFifo(256));
    int vals[] = {1, 2, 3};
    for (auto v : vals) ufifo_put(fifo_, &v, sizeof(v));
    ufifo_skip(fifo_);
    // after skip, fifo should be empty for bytestream (no recsize, skip has no effect)
    // Actually for bytestream without recsize, skip clears everything
}

TEST_F(ByteSoleSingle, SizeAndLen) {
    GenerateName("bs_sizelen");
    ASSERT_EQ(0, CreateFifo(256));
    EXPECT_GT(ufifo_size(fifo_), 0u);
    EXPECT_EQ(0u, ufifo_len(fifo_));
    int val = 1;
    ufifo_put(fifo_, &val, sizeof(val));
    EXPECT_EQ(sizeof(int), ufifo_len(fifo_));
}

TEST_F(ByteSoleSingle, Reset) {
    GenerateName("bs_reset");
    ASSERT_EQ(0, CreateFifo(256));
    int val = 1;
    ufifo_put(fifo_, &val, sizeof(val));
    EXPECT_GT(ufifo_len(fifo_), 0u);
    ufifo_reset(fifo_);
    EXPECT_EQ(0u, ufifo_len(fifo_));
}

TEST_F(ByteSoleSingle, FifoFullEmpty) {
    GenerateName("bs_fullmt");
    ASSERT_EQ(0, CreateFifo(64));
    // Empty: get returns 0
    int out = -1;
    EXPECT_EQ(0u, ufifo_get(fifo_, &out, sizeof(out)));
    // Fill until full
    int val = 1;
    unsigned int total = 0;
    while (ufifo_put(fifo_, &val, sizeof(val)) > 0) total += sizeof(val);
    EXPECT_GT(total, 0u);
    // Full: put returns 0
    EXPECT_EQ(0u, ufifo_put(fifo_, &val, sizeof(val)));
}

TEST_F(ByteSoleSingle, LargeDataThroughput) {
    GenerateName("bs_throughput");
    ASSERT_EQ(0, CreateFifo(4096));
    for (int i = 0; i < 1000; i++) {
        ufifo_put(fifo_, &i, sizeof(i));
        int out = -1;
        ufifo_get(fifo_, &out, sizeof(out));
        EXPECT_EQ(i, out);
    }
}

// 2.2 SPSC
class ByteSoleSPSC : public BytestreamFixture {};

TEST_F(ByteSoleSPSC, Basic) {
    GenerateName("bs_spsc");
    ASSERT_EQ(0, CreateFifo(1024, UFIFO_LOCK_THREAD));
    std::atomic<bool> done{false};
    std::thread producer([&]() {
        for (int i = 0; i < 100; i++) {
            while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                std::this_thread::yield();
        }
        done = true;
    });
    int received = 0;
    while (received < 100) {
        int out;
        if (ufifo_get(fifo_, &out, sizeof(out)) > 0) {
            EXPECT_EQ(received, out);
            received++;
        } else {
            std::this_thread::yield();
        }
    }
    producer.join();
}

TEST_F(ByteSoleSPSC, Boundary) {
    GenerateName("bs_spsc_bnd");
    ASSERT_EQ(0, CreateFifo(64, UFIFO_LOCK_THREAD));
    std::thread producer([&]() {
        for (int i = 0; i < 50; i++) {
            while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < 50) {
        int out;
        if (ufifo_get(fifo_, &out, sizeof(out)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(50, count);
}

TEST_F(ByteSoleSPSC, Stress) {
    GenerateName("bs_spsc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int N = 5000;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        int out;
        if (ufifo_get(fifo_, &out, sizeof(out)) > 0) {
            EXPECT_EQ(count, out);
            count++;
        } else {
            std::this_thread::yield();
        }
    }
    producer.join();
}

// 2.3 SPMC (SOLE: consumers compete)
class ByteSoleSPMC : public BytestreamFixture {};

TEST_F(ByteSoleSPMC, Basic) {
    GenerateName("bs_spmc");
    ASSERT_EQ(0, CreateFifo(1024, UFIFO_LOCK_THREAD));
    const int N = 100;
    std::atomic<int> consumed{0};
    // Producer
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                std::this_thread::yield();
        }
    });
    // 2 consumers competing
    auto consumer_fn = [&]() {
        while (consumed < N) {
            int out;
            if (ufifo_get(fifo_, &out, sizeof(out)) > 0)
                consumed++;
            else
                std::this_thread::yield();
        }
    };
    std::thread c1(consumer_fn), c2(consumer_fn);
    producer.join(); c1.join(); c2.join();
    EXPECT_EQ(N, consumed.load());
}

TEST_F(ByteSoleSPMC, Boundary) {
    GenerateName("bs_spmc_bnd");
    ASSERT_EQ(0, CreateFifo(64, UFIFO_LOCK_THREAD));
    int val = 42;
    ufifo_put(fifo_, &val, sizeof(val));
    // Only 1 of 2 consumers should get it
    std::atomic<int> got{0};
    auto fn = [&]() {
        int out;
        if (ufifo_get(fifo_, &out, sizeof(out)) > 0) got++;
    };
    std::thread c1(fn), c2(fn);
    c1.join(); c2.join();
    EXPECT_EQ(1, got.load());
}

TEST_F(ByteSoleSPMC, Stress) {
    GenerateName("bs_spmc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int N = 2000;
    std::atomic<int> consumed{0};
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                std::this_thread::yield();
        }
    });
    std::vector<std::thread> consumers;
    for (int c = 0; c < 4; c++) {
        consumers.emplace_back([&]() {
            while (consumed < N) {
                int out;
                if (ufifo_get(fifo_, &out, sizeof(out)) > 0)
                    consumed++;
                else
                    std::this_thread::yield();
            }
        });
    }
    producer.join();
    for (auto& t : consumers) t.join();
    EXPECT_EQ(N, consumed.load());
}

// 2.4 MPSC
class ByteSoleMPSC : public BytestreamFixture {};

TEST_F(ByteSoleMPSC, Basic) {
    GenerateName("bs_mpsc");
    ASSERT_EQ(0, CreateFifo(2048, UFIFO_LOCK_THREAD));
    const int PER_PRODUCER = 50;
    const int NUM_PRODUCERS = 4;
    std::vector<std::thread> producers;
    for (int p = 0; p < NUM_PRODUCERS; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER_PRODUCER; i++) {
                while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    const int TOTAL = PER_PRODUCER * NUM_PRODUCERS;
    while (count < TOTAL) {
        int out;
        if (ufifo_get(fifo_, &out, sizeof(out)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

TEST_F(ByteSoleMPSC, Boundary) {
    GenerateName("bs_mpsc_bnd");
    ASSERT_EQ(0, CreateFifo(64, UFIFO_LOCK_THREAD));
    std::atomic<int> success{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 4; p++) {
        producers.emplace_back([&]() {
            int val = 1;
            if (ufifo_put(fifo_, &val, sizeof(val)) > 0) success++;
        });
    }
    for (auto& t : producers) t.join();
    EXPECT_GE(success.load(), 1);
}

TEST_F(ByteSoleMPSC, Stress) {
    GenerateName("bs_mpsc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int PER_PRODUCER = 500;
    const int NUM_PRODUCERS = 4;
    const int TOTAL = PER_PRODUCER * NUM_PRODUCERS;
    std::atomic<bool> done{false};
    std::vector<std::thread> producers;
    for (int p = 0; p < NUM_PRODUCERS; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER_PRODUCER; i++) {
                while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        int out;
        if (ufifo_get(fifo_, &out, sizeof(out)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

// 2.5 MPMC (SOLE: consumers compete)
class ByteSoleMPMC : public BytestreamFixture {};

TEST_F(ByteSoleMPMC, Basic) {
    GenerateName("bs_mpmc");
    ASSERT_EQ(0, CreateFifo(2048, UFIFO_LOCK_THREAD));
    const int TOTAL = 200;
    std::atomic<int> produced{0}, consumed{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 2; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < TOTAL / 2; i++) {
                while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                    std::this_thread::yield();
                produced++;
            }
        });
    }
    for (int c = 0; c < 2; c++) {
        threads.emplace_back([&]() {
            while (consumed < TOTAL) {
                int out;
                if (ufifo_get(fifo_, &out, sizeof(out)) > 0)
                    consumed++;
                else
                    std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL, consumed.load());
}

TEST_F(ByteSoleMPMC, Boundary) {
    GenerateName("bs_mpmc_bnd");
    ASSERT_EQ(0, CreateFifo(64, UFIFO_LOCK_THREAD));
    std::atomic<int> produced{0}, consumed{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 2; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 10; i++) {
                int val = i;
                if (ufifo_put(fifo_, &val, sizeof(val)) > 0) produced++;
                std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    // drain
    int out;
    while (ufifo_get(fifo_, &out, sizeof(out)) > 0) consumed++;
    EXPECT_EQ(produced.load(), consumed.load());
}

TEST_F(ByteSoleMPMC, Stress) {
    GenerateName("bs_mpmc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int TOTAL = 2000;
    std::atomic<int> consumed{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 4; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < TOTAL / 4; i++) {
                while (ufifo_put(fifo_, &i, sizeof(i)) == 0)
                    std::this_thread::yield();
            }
        });
    }
    for (int c = 0; c < 4; c++) {
        threads.emplace_back([&]() {
            while (consumed < TOTAL) {
                int out;
                if (ufifo_get(fifo_, &out, sizeof(out)) > 0)
                    consumed++;
                else
                    std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL, consumed.load());
}

// =============================================================================
// Part 3: Bytestream + SHARED
// =============================================================================

// 3.1 Single instance
class ByteSharedSingle : public MultiUserFixture {
protected:
    int CreateProducer(unsigned int size, unsigned int max_users = 10) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_THREAD;
        init.alloc.data_mode = UFIFO_DATA_SHARED;
        init.alloc.max_users = max_users;
        ufifo_t* fifo = nullptr;
        int ret = ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo);
        if (ret == 0) fifos_.push_back(fifo);
        return ret;
    }
};

TEST_F(ByteSharedSingle, AllocAttach) {
    GenerateName("bsh_alloc");
    ASSERT_EQ(0, CreateProducer(256));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);
}

TEST_F(ByteSharedSingle, BasicPutGet) {
    GenerateName("bsh_basic");
    ASSERT_EQ(0, CreateProducer(256));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    int val = 42;
    EXPECT_EQ(sizeof(val), ufifo_put(fifos_[0], &val, sizeof(val)));
    int out = 0;
    EXPECT_EQ(sizeof(out), ufifo_get(consumer, &out, sizeof(out)));
    EXPECT_EQ(42, out);
}

TEST_F(ByteSharedSingle, SizeAndLen) {
    GenerateName("bsh_sizelen");
    ASSERT_EQ(0, CreateProducer(256));
    EXPECT_GT(ufifo_size(fifos_[0]), 0u);
    EXPECT_EQ(0u, ufifo_len(fifos_[0]));
}

TEST_F(ByteSharedSingle, Reset) {
    GenerateName("bsh_reset");
    ASSERT_EQ(0, CreateProducer(256));
    int val = 1;
    ufifo_put(fifos_[0], &val, sizeof(val));
    ufifo_reset(fifos_[0]);
    EXPECT_EQ(0u, ufifo_len(fifos_[0]));
}

TEST_F(ByteSharedSingle, FifoFullEmpty) {
    GenerateName("bsh_fullmt");
    ASSERT_EQ(0, CreateProducer(64));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    int out = -1;
    EXPECT_EQ(0u, ufifo_get(consumer, &out, sizeof(out)));
    int val = 1;
    unsigned int count = 0;
    while (ufifo_put(fifos_[0], &val, sizeof(val)) > 0) count++;
    EXPECT_GT(count, 0u);
    EXPECT_EQ(0u, ufifo_put(fifos_[0], &val, sizeof(val)));
}

TEST_F(ByteSharedSingle, LargeDataThroughput) {
    GenerateName("bsh_throughput");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    for (int i = 0; i < 1000; i++) {
        ufifo_put(fifos_[0], &i, sizeof(i));
        int out = -1;
        ufifo_get(consumer, &out, sizeof(out));
        EXPECT_EQ(i, out);
    }
}

// 3.2 SPSC
class ByteSharedSPSC : public ByteSharedSingle {};

TEST_F(ByteSharedSPSC, Basic) {
    GenerateName("bsh_spsc");
    ASSERT_EQ(0, CreateProducer(1024));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    const int N = 100;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        int out;
        if (ufifo_get(consumer, &out, sizeof(out)) > 0) {
            EXPECT_EQ(count, out);
            count++;
        } else {
            std::this_thread::yield();
        }
    }
    producer.join();
}

TEST_F(ByteSharedSPSC, Boundary) {
    GenerateName("bsh_spsc_bnd");
    ASSERT_EQ(0, CreateProducer(64));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    std::thread producer([&]() {
        for (int i = 0; i < 20; i++) {
            while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                std::this_thread::yield();
            // Advance producer's out so min(all_outs) moves
            int discard;
            ufifo_get(fifos_[0], &discard, sizeof(discard));
        }
    });
    int count = 0;
    while (count < 20) {
        int out;
        if (ufifo_get(consumer, &out, sizeof(out)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(20, count);
}

TEST_F(ByteSharedSPSC, Stress) {
    GenerateName("bsh_spsc_str");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    const int N = 5000;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                std::this_thread::yield();
            // Advance producer's out so min(all_outs) moves and space is reclaimed
            int discard;
            ufifo_get(fifos_[0], &discard, sizeof(discard));
        }
    });
    int count = 0;
    while (count < N) {
        int out;
        if (ufifo_get(consumer, &out, sizeof(out)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

// 3.3 SPMC (SHARED: broadcast to all consumers)
class ByteSharedSPMC : public ByteSharedSingle {};

TEST_F(ByteSharedSPMC, Broadcast) {
    GenerateName("bsh_spmc");
    ASSERT_EQ(0, CreateProducer(1024));
    const int NUM_CONSUMERS = 3;
    std::vector<ufifo_t*> consumers(NUM_CONSUMERS);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachConsumer(&c));
        fifos_.push_back(c);
    }

    const int N = 50;
    for (int i = 0; i < N; i++)
        ufifo_put(fifos_[0], &i, sizeof(i));

    // Each consumer should receive ALL messages
    for (auto& c : consumers) {
        int count = 0;
        int out;
        while (ufifo_get(c, &out, sizeof(out)) > 0) count++;
        EXPECT_EQ(N, count);
    }
}

TEST_F(ByteSharedSPMC, ConsumerIndependence) {
    GenerateName("bsh_spmc_ind");
    ASSERT_EQ(0, CreateProducer(1024));
    ufifo_t *c1 = nullptr, *c2 = nullptr;
    ASSERT_EQ(0, AttachConsumer(&c1));
    ASSERT_EQ(0, AttachConsumer(&c2));
    fifos_.push_back(c1);
    fifos_.push_back(c2);

    for (int i = 0; i < 10; i++)
        ufifo_put(fifos_[0], &i, sizeof(i));

    // c1 reads 5 items, c2 reads all 10
    for (int i = 0; i < 5; i++) {
        int out;
        ufifo_get(c1, &out, sizeof(out));
    }
    int c2_count = 0;
    int out;
    while (ufifo_get(c2, &out, sizeof(out)) > 0) c2_count++;
    EXPECT_EQ(10, c2_count);

    // c1 should still have 5 remaining
    int c1_count = 0;
    while (ufifo_get(c1, &out, sizeof(out)) > 0) c1_count++;
    EXPECT_EQ(5, c1_count);
}

TEST_F(ByteSharedSPMC, Stress) {
    GenerateName("bsh_spmc_str");
    ASSERT_EQ(0, CreateProducer(4096));
    const int NUM_CONSUMERS = 4;
    std::vector<ufifo_t*> consumers(NUM_CONSUMERS);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachConsumer(&c));
        fifos_.push_back(c);
    }

    const int N = 500;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                std::this_thread::yield();
            // Advance producer's out so min(all_outs) moves
            int discard;
            ufifo_get(fifos_[0], &discard, sizeof(discard));
        }
    });

    std::vector<std::thread> consumer_threads;
    std::atomic<int> total_received{0};
    for (auto& c : consumers) {
        consumer_threads.emplace_back([&, c]() {
            int count = 0;
            while (count < N) {
                int out;
                if (ufifo_get(c, &out, sizeof(out)) > 0) count++;
                else std::this_thread::yield();
            }
            total_received += count;
        });
    }

    producer.join();
    for (auto& t : consumer_threads) t.join();
    // Each of 4 consumers got N messages
    EXPECT_EQ(N * NUM_CONSUMERS, total_received.load());
}

// 3.4 MPSC
class ByteSharedMPSC : public ByteSharedSingle {};

TEST_F(ByteSharedMPSC, Basic) {
    GenerateName("bsh_mpsc");
    ASSERT_EQ(0, CreateProducer(2048));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    const int PER = 50, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        int out;
        if (ufifo_get(consumer, &out, sizeof(out)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

TEST_F(ByteSharedMPSC, Boundary) {
    GenerateName("bsh_mpsc_bnd");
    ASSERT_EQ(0, CreateProducer(64));
    std::atomic<int> success{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 4; p++) {
        producers.emplace_back([&]() {
            int val = 1;
            if (ufifo_put(fifos_[0], &val, sizeof(val)) > 0) success++;
        });
    }
    for (auto& t : producers) t.join();
    EXPECT_GE(success.load(), 1);
}

TEST_F(ByteSharedMPSC, Stress) {
    GenerateName("bsh_mpsc_str");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    const int PER = 500, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                    std::this_thread::yield();
                // Advance producer's out so min(all_outs) moves
                int discard;
                ufifo_get(fifos_[0], &discard, sizeof(discard));
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        int out;
        if (ufifo_get(consumer, &out, sizeof(out)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

// 3.5 MPMC (SHARED: broadcast + concurrent producers)
class ByteSharedMPMC : public ByteSharedSingle {};

TEST_F(ByteSharedMPMC, BroadcastConcurrent) {
    GenerateName("bsh_mpmc");
    ASSERT_EQ(0, CreateProducer(4096));
    const int NC = 2;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachConsumer(&c));
        fifos_.push_back(c);
    }

    const int PER = 50, NP = 2, TOTAL = PER * NP;
    std::vector<std::thread> threads;
    // Producers
    for (int p = 0; p < NP; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                    std::this_thread::yield();
            }
        });
    }
    // Consumers
    std::atomic<int> total_received{0};
    for (auto& c : consumers) {
        threads.emplace_back([&, c]() {
            int count = 0;
            while (count < TOTAL) {
                int out;
                if (ufifo_get(c, &out, sizeof(out)) > 0) count++;
                else std::this_thread::yield();
            }
            total_received += count;
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL * NC, total_received.load());
}

TEST_F(ByteSharedMPMC, Boundary) {
    GenerateName("bsh_mpmc_bnd");
    ASSERT_EQ(0, CreateProducer(64));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachConsumer(&consumer));
    fifos_.push_back(consumer);

    std::atomic<int> produced{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 2; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < 5; i++) {
                int val = i;
                if (ufifo_put(fifos_[0], &val, sizeof(val)) > 0) produced++;
                std::this_thread::yield();
            }
        });
    }
    for (auto& t : producers) t.join();
    int consumed = 0, out;
    while (ufifo_get(consumer, &out, sizeof(out)) > 0) consumed++;
    EXPECT_EQ(produced.load(), consumed);
}

TEST_F(ByteSharedMPMC, Stress) {
    GenerateName("bsh_mpmc_str");
    ASSERT_EQ(0, CreateProducer(8192));
    const int NC = 3;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachConsumer(&c));
        fifos_.push_back(c);
    }

    const int PER = 200, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> threads;
    for (int p = 0; p < NP; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                while (ufifo_put(fifos_[0], &i, sizeof(i)) == 0)
                    std::this_thread::yield();
                // Advance producer's out so min(all_outs) moves
                int discard;
                ufifo_get(fifos_[0], &discard, sizeof(discard));
            }
        });
    }
    std::atomic<int> total_received{0};
    for (auto& c : consumers) {
        threads.emplace_back([&, c]() {
            int count = 0;
            while (count < TOTAL) {
                int out;
                if (ufifo_get(c, &out, sizeof(out)) > 0) count++;
                else std::this_thread::yield();
            }
            total_received += count;
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL * NC, total_received.load());
}

// =============================================================================
// Part 4: Record + SOLE
// =============================================================================

// 4.1 Single instance
class RecSoleSingle : public RecordFixture {};

TEST_F(RecSoleSingle, OpenClose) {
    GenerateName("rs_open");
    ASSERT_EQ(0, CreateFifo(512));
    EXPECT_NE(nullptr, fifo_);
}

TEST_F(RecSoleSingle, BasicPutGet) {
    GenerateName("rs_basic");
    ASSERT_EQ(0, CreateFifo(512));
    char buf[128];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    rec->size = 5;
    memcpy(rec->data, "hello", 5);
    EXPECT_EQ(sizeof(TestRecord) + 5, ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size));

    char out_buf[128] = {};
    TestRecord* out = reinterpret_cast<TestRecord*>(out_buf);
    EXPECT_EQ(sizeof(TestRecord) + 5, ufifo_get(fifo_, out, sizeof(out_buf)));
    EXPECT_EQ(5u, out->size);
    EXPECT_EQ(0, memcmp(out->data, "hello", 5));
}

TEST_F(RecSoleSingle, PeekLen) {
    GenerateName("rs_peeklen");
    ASSERT_EQ(0, CreateFifo(512));
    char buf[128];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    rec->size = 10;
    memset(rec->data, 'x', 10);
    ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);
    EXPECT_EQ(sizeof(TestRecord) + 10, ufifo_peek_len(fifo_));
}

TEST_F(RecSoleSingle, SkipRecord) {
    GenerateName("rs_skip");
    ASSERT_EQ(0, CreateFifo(512));
    char buf[128];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    // Put 2 records
    rec->size = 3; memcpy(rec->data, "aaa", 3);
    ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);
    rec->size = 3; memcpy(rec->data, "bbb", 3);
    ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);

    ufifo_skip(fifo_);  // skip first record
    char out_buf[128] = {};
    TestRecord* out = reinterpret_cast<TestRecord*>(out_buf);
    ufifo_get(fifo_, out, sizeof(out_buf));
    EXPECT_EQ(0, memcmp(out->data, "bbb", 3));
}

TEST_F(RecSoleSingle, WrapAround) {
    GenerateName("rs_wrap");
    ASSERT_EQ(0, CreateFifo(128));
    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);

    // Fill and drain to move the internal pointers forward
    for (int round = 0; round < 5; round++) {
        rec->size = 10;
        memset(rec->data, 'a' + round, rec->size);
        ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);
        char out_buf[64] = {};
        ufifo_get(fifo_, out_buf, sizeof(out_buf));
    }

    // Now put a record that should wrap around the buffer boundary
    rec->size = 20;
    memset(rec->data, 'z', rec->size);
    EXPECT_GT(ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size), 0u);
    char out_buf[64] = {};
    TestRecord* out = reinterpret_cast<TestRecord*>(out_buf);
    EXPECT_GT(ufifo_get(fifo_, out, sizeof(out_buf)), 0u);
    EXPECT_EQ(20u, out->size);
    EXPECT_EQ(0, memcmp(out->data, std::string(20, 'z').c_str(), 20));
}

TEST_F(RecSoleSingle, FifoFullEmpty) {
    GenerateName("rs_fullmt");
    ASSERT_EQ(0, CreateFifo(128));
    char out_buf[64] = {};
    EXPECT_EQ(0u, ufifo_get(fifo_, out_buf, sizeof(out_buf)));

    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    int count = 0;
    while (true) {
        rec->size = 8;
        memset(rec->data, 'x', 8);
        if (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0) break;
        count++;
    }
    EXPECT_GT(count, 0);
}

TEST_F(RecSoleSingle, LargeDataThroughput) {
    GenerateName("rs_throughput");
    ASSERT_EQ(0, CreateFifo(4096));
    char buf[64], out_buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    for (int i = 0; i < 500; i++) {
        rec->size = 4;
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);
        TestRecord* out = reinterpret_cast<TestRecord*>(out_buf);
        ufifo_get(fifo_, out, sizeof(out_buf));
        int val;
        memcpy(&val, out->data, sizeof(val));
        EXPECT_EQ(i, val);
    }
}

// 4.2 SPSC
class RecSoleSPSC : public RecordFixture {};

TEST_F(RecSoleSPSC, Basic) {
    GenerateName("rs_spsc");
    ASSERT_EQ(0, CreateFifo(2048, UFIFO_LOCK_THREAD));
    const int N = 100;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

TEST_F(RecSoleSPSC, Boundary) {
    GenerateName("rs_spsc_bnd");
    ASSERT_EQ(0, CreateFifo(128, UFIFO_LOCK_THREAD));
    std::thread producer([&]() {
        for (int i = 0; i < 20; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < 20) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(20, count);
}

TEST_F(RecSoleSPSC, Stress) {
    GenerateName("rs_spsc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int N = 3000;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

// 4.3 SPMC
class RecSoleSPMC : public RecordFixture {};

TEST_F(RecSoleSPMC, Basic) {
    GenerateName("rs_spmc");
    ASSERT_EQ(0, CreateFifo(2048, UFIFO_LOCK_THREAD));
    const int N = 100;
    std::atomic<int> consumed{0};
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    auto consumer_fn = [&]() {
        while (consumed < N) {
            char out_buf[32];
            if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
            else std::this_thread::yield();
        }
    };
    std::thread c1(consumer_fn), c2(consumer_fn);
    producer.join(); c1.join(); c2.join();
    EXPECT_EQ(N, consumed.load());
}

TEST_F(RecSoleSPMC, Boundary) {
    GenerateName("rs_spmc_bnd");
    ASSERT_EQ(0, CreateFifo(128, UFIFO_LOCK_THREAD));
    char buf[32];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    rec->size = 4;
    memset(rec->data, 'x', 4);
    ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);

    std::atomic<int> got{0};
    auto fn = [&]() {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) got++;
    };
    std::thread c1(fn), c2(fn);
    c1.join(); c2.join();
    EXPECT_EQ(1, got.load());
}

TEST_F(RecSoleSPMC, Stress) {
    GenerateName("rs_spmc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int N = 1000;
    std::atomic<int> consumed{0};
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    std::vector<std::thread> consumers;
    for (int c = 0; c < 4; c++) {
        consumers.emplace_back([&]() {
            while (consumed < N) {
                char out_buf[32];
                if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
                else std::this_thread::yield();
            }
        });
    }
    producer.join();
    for (auto& t : consumers) t.join();
    EXPECT_EQ(N, consumed.load());
}

// 4.4 MPSC
class RecSoleMPSC : public RecordFixture {};

TEST_F(RecSoleMPSC, Basic) {
    GenerateName("rs_mpsc");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int PER = 50, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

TEST_F(RecSoleMPSC, Boundary) {
    GenerateName("rs_mpsc_bnd");
    ASSERT_EQ(0, CreateFifo(128, UFIFO_LOCK_THREAD));
    std::atomic<int> success{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 4; p++) {
        producers.emplace_back([&]() {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = 4;
            if (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) > 0) success++;
        });
    }
    for (auto& t : producers) t.join();
    EXPECT_GE(success.load(), 1);
}

TEST_F(RecSoleMPSC, Stress) {
    GenerateName("rs_mpsc_str");
    ASSERT_EQ(0, CreateFifo(8192, UFIFO_LOCK_THREAD));
    const int PER = 300, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

// 4.5 MPMC
class RecSoleMPMC : public RecordFixture {};

TEST_F(RecSoleMPMC, Basic) {
    GenerateName("rs_mpmc");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int TOTAL = 200;
    std::atomic<int> consumed{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 2; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < TOTAL / 2; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    for (int c = 0; c < 2; c++) {
        threads.emplace_back([&]() {
            while (consumed < TOTAL) {
                char out_buf[32];
                if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
                else std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL, consumed.load());
}

TEST_F(RecSoleMPMC, Boundary) {
    GenerateName("rs_mpmc_bnd");
    ASSERT_EQ(0, CreateFifo(128, UFIFO_LOCK_THREAD));
    std::atomic<int> produced{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 2; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 5; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = 4;
                if (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) > 0) produced++;
                std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    int consumed = 0;
    char out_buf[32];
    while (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
    EXPECT_EQ(produced.load(), consumed);
}

TEST_F(RecSoleMPMC, Stress) {
    GenerateName("rs_mpmc_str");
    ASSERT_EQ(0, CreateFifo(8192, UFIFO_LOCK_THREAD));
    const int TOTAL = 1000;
    std::atomic<int> consumed{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 4; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < TOTAL / 4; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    for (int c = 0; c < 4; c++) {
        threads.emplace_back([&]() {
            while (consumed < TOTAL) {
                char out_buf[32];
                if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
                else std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL, consumed.load());
}

// =============================================================================
// Part 5: Record + SHARED
// =============================================================================

// Shared record multi-user fixture
class RecSharedFixture : public MultiUserFixture {
protected:
    int CreateProducer(unsigned int size, unsigned int max_users = 10) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_THREAD;
        init.alloc.data_mode = UFIFO_DATA_SHARED;
        init.alloc.max_users = max_users;
        init.hook.recsize = test_recsize;
        ufifo_t* fifo = nullptr;
        int ret = ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo);
        if (ret == 0) fifos_.push_back(fifo);
        return ret;
    }

    int AttachRecordConsumer(ufifo_t** handle) {
        ufifo_hook_t hook = {};
        hook.recsize = test_recsize;
        return AttachConsumer(handle, hook);
    }
};

// 5.1 Single instance
class RecSharedSingle : public RecSharedFixture {};

TEST_F(RecSharedSingle, AllocAttach) {
    GenerateName("rsh_alloc");
    ASSERT_EQ(0, CreateProducer(512));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);
}

TEST_F(RecSharedSingle, BasicPutGet) {
    GenerateName("rsh_basic");
    ASSERT_EQ(0, CreateProducer(512));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    rec->size = 5;
    memcpy(rec->data, "hello", 5);
    EXPECT_GT(ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size), 0u);

    char out_buf[64] = {};
    TestRecord* out = reinterpret_cast<TestRecord*>(out_buf);
    EXPECT_GT(ufifo_get(consumer, out, sizeof(out_buf)), 0u);
    EXPECT_EQ(5u, out->size);
    EXPECT_EQ(0, memcmp(out->data, "hello", 5));
}

TEST_F(RecSharedSingle, PeekLen) {
    GenerateName("rsh_peeklen");
    ASSERT_EQ(0, CreateProducer(512));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    rec->size = 8;
    memset(rec->data, 'a', 8);
    ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size);
    EXPECT_EQ(sizeof(TestRecord) + 8, ufifo_peek_len(consumer));
}

TEST_F(RecSharedSingle, SkipRecord) {
    GenerateName("rsh_skip");
    ASSERT_EQ(0, CreateProducer(512));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    rec->size = 3; memcpy(rec->data, "aaa", 3);
    ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size);
    rec->size = 3; memcpy(rec->data, "bbb", 3);
    ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size);

    ufifo_skip(consumer);
    char out_buf[64] = {};
    TestRecord* out = reinterpret_cast<TestRecord*>(out_buf);
    ufifo_get(consumer, out, sizeof(out_buf));
    EXPECT_EQ(0, memcmp(out->data, "bbb", 3));
}

TEST_F(RecSharedSingle, FifoFullEmpty) {
    GenerateName("rsh_fullmt");
    ASSERT_EQ(0, CreateProducer(128));
    char out_buf[64] = {};
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);
    EXPECT_EQ(0u, ufifo_get(consumer, out_buf, sizeof(out_buf)));

    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
    int count = 0;
    while (true) {
        rec->size = 8;
        if (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0) break;
        count++;
    }
    EXPECT_GT(count, 0);
}

TEST_F(RecSharedSingle, LargeDataThroughput) {
    GenerateName("rsh_throughput");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    for (int i = 0; i < 500; i++) {
        char buf[32];
        TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
        rec->size = sizeof(int);
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size);
        char out_buf[32] = {};
        TestRecord* out = reinterpret_cast<TestRecord*>(out_buf);
        ufifo_get(consumer, out, sizeof(out_buf));
        int val;
        memcpy(&val, out->data, sizeof(val));
        EXPECT_EQ(i, val);
    }
}

// 5.2 SPSC
class RecSharedSPSC : public RecSharedFixture {};

TEST_F(RecSharedSPSC, Basic) {
    GenerateName("rsh_spsc");
    ASSERT_EQ(0, CreateProducer(2048));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    const int N = 100;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

TEST_F(RecSharedSPSC, Boundary) {
    GenerateName("rsh_spsc_bnd");
    ASSERT_EQ(0, CreateProducer(256));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    std::thread producer([&]() {
        for (int i = 0; i < 20; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < 20) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(20, count);
}

TEST_F(RecSharedSPSC, Stress) {
    GenerateName("rsh_spsc_str");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    const int N = 3000;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
            // Advance producer's out so min(all_outs) moves
            char discard[32];
            ufifo_get(fifos_[0], discard, sizeof(discard));
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

// 5.3 SPMC (broadcast)
class RecSharedSPMC : public RecSharedFixture {};

TEST_F(RecSharedSPMC, Broadcast) {
    GenerateName("rsh_spmc");
    ASSERT_EQ(0, CreateProducer(2048));
    const int NC = 3;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachRecordConsumer(&c));
        fifos_.push_back(c);
    }

    const int N = 50;
    for (int i = 0; i < N; i++) {
        char buf[32];
        TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
        rec->size = sizeof(int);
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size);
    }

    for (auto& c : consumers) {
        int count = 0;
        char out_buf[32];
        while (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
        EXPECT_EQ(N, count);
    }
}

TEST_F(RecSharedSPMC, ConsumerIndependence) {
    GenerateName("rsh_spmc_ind");
    ASSERT_EQ(0, CreateProducer(2048));
    ufifo_t *c1 = nullptr, *c2 = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&c1));
    ASSERT_EQ(0, AttachRecordConsumer(&c2));
    fifos_.push_back(c1);
    fifos_.push_back(c2);

    for (int i = 0; i < 10; i++) {
        char buf[32];
        TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
        rec->size = sizeof(int);
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size);
    }

    // c1 reads 5, c2 reads all 10
    for (int i = 0; i < 5; i++) {
        char out_buf[32];
        ufifo_get(c1, out_buf, sizeof(out_buf));
    }
    int c2_count = 0;
    char out_buf[32];
    while (ufifo_get(c2, out_buf, sizeof(out_buf)) > 0) c2_count++;
    EXPECT_EQ(10, c2_count);
    int c1_count = 0;
    while (ufifo_get(c1, out_buf, sizeof(out_buf)) > 0) c1_count++;
    EXPECT_EQ(5, c1_count);
}

TEST_F(RecSharedSPMC, Stress) {
    GenerateName("rsh_spmc_str");
    ASSERT_EQ(0, CreateProducer(4096));
    const int NC = 4;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachRecordConsumer(&c));
        fifos_.push_back(c);
    }

    const int N = 300;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                std::this_thread::yield();
            // Advance producer's out so min(all_outs) moves
            char discard[32];
            ufifo_get(fifos_[0], discard, sizeof(discard));
        }
    });
    std::vector<std::thread> consumer_threads;
    std::atomic<int> total{0};
    for (auto& c : consumers) {
        consumer_threads.emplace_back([&, c]() {
            int count = 0;
            while (count < N) {
                char out_buf[32];
                if (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
                else std::this_thread::yield();
            }
            total += count;
        });
    }
    producer.join();
    for (auto& t : consumer_threads) t.join();
    EXPECT_EQ(N * NC, total.load());
}

// 5.4 MPSC
class RecSharedMPSC : public RecSharedFixture {};

TEST_F(RecSharedMPSC, Basic) {
    GenerateName("rsh_mpsc");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    const int PER = 50, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

TEST_F(RecSharedMPSC, Boundary) {
    GenerateName("rsh_mpsc_bnd");
    ASSERT_EQ(0, CreateProducer(128));
    std::atomic<int> success{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 4; p++) {
        producers.emplace_back([&]() {
            char buf[32];
            TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
            rec->size = 4;
            if (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) > 0) success++;
        });
    }
    for (auto& t : producers) t.join();
    EXPECT_GE(success.load(), 1);
}

TEST_F(RecSharedMPSC, Stress) {
    GenerateName("rsh_mpsc_str");
    ASSERT_EQ(0, CreateProducer(8192));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    const int PER = 300, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
                // Advance producer's out so min(all_outs) moves
                char discard[32];
                ufifo_get(fifos_[0], discard, sizeof(discard));
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

// 5.5 MPMC
class RecSharedMPMC : public RecSharedFixture {};

TEST_F(RecSharedMPMC, BroadcastConcurrent) {
    GenerateName("rsh_mpmc");
    ASSERT_EQ(0, CreateProducer(4096));
    const int NC = 2;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachRecordConsumer(&c));
        fifos_.push_back(c);
    }

    const int PER = 50, NP = 2, TOTAL = PER * NP;
    std::vector<std::thread> threads;
    for (int p = 0; p < NP; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    std::atomic<int> total{0};
    for (auto& c : consumers) {
        threads.emplace_back([&, c]() {
            int count = 0;
            while (count < TOTAL) {
                char out_buf[32];
                if (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
                else std::this_thread::yield();
            }
            total += count;
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL * NC, total.load());
}

TEST_F(RecSharedMPMC, Boundary) {
    GenerateName("rsh_mpmc_bnd");
    ASSERT_EQ(0, CreateProducer(128));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachRecordConsumer(&consumer));
    fifos_.push_back(consumer);

    std::atomic<int> produced{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 2; p++) {
        producers.emplace_back([&]() {
            for (int i = 0; i < 5; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = 4;
                if (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) > 0) produced++;
                std::this_thread::yield();
            }
        });
    }
    for (auto& t : producers) t.join();
    int consumed = 0;
    char out_buf[32];
    while (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) consumed++;
    EXPECT_EQ(produced.load(), consumed);
}

TEST_F(RecSharedMPMC, Stress) {
    GenerateName("rsh_mpmc_str");
    ASSERT_EQ(0, CreateProducer(8192));
    const int NC = 3;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachRecordConsumer(&c));
        fifos_.push_back(c);
    }

    const int PER = 150, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> threads;
    for (int p = 0; p < NP; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TestRecord* rec = reinterpret_cast<TestRecord*>(buf);
                rec->size = sizeof(int);
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TestRecord) + rec->size) == 0)
                    std::this_thread::yield();
                // Advance producer's out so min(all_outs) moves
                char discard[32];
                ufifo_get(fifos_[0], discard, sizeof(discard));
            }
        });
    }
    std::atomic<int> total{0};
    for (auto& c : consumers) {
        threads.emplace_back([&, c]() {
            int count = 0;
            while (count < TOTAL) {
                char out_buf[32];
                if (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
                else std::this_thread::yield();
            }
            total += count;
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL * NC, total.load());
}

// =============================================================================
// Part 6: Tag + SOLE
// =============================================================================

// 6.1 Single instance
class TagSoleSingle : public TagFixture {};

TEST_F(TagSoleSingle, OpenClose) {
    GenerateName("ts_open");
    ASSERT_EQ(0, CreateFifo(512));
    EXPECT_NE(nullptr, fifo_);
}

TEST_F(TagSoleSingle, BasicPutGet) {
    GenerateName("ts_basic");
    ASSERT_EQ(0, CreateFifo(512));
    PutTaggedRecord(1, "hello");
    char out_buf[128] = {};
    TaggedRecord* out = reinterpret_cast<TaggedRecord*>(out_buf);
    EXPECT_GT(ufifo_get(fifo_, out, sizeof(out_buf)), 0u);
    EXPECT_EQ(1u, out->tag);
    EXPECT_EQ(0, memcmp(out->data, "hello", 5));
}

TEST_F(TagSoleSingle, OldestByTag) {
    GenerateName("ts_oldest");
    ASSERT_EQ(0, CreateFifo(1024));
    PutTaggedRecord(1, "first_1");
    PutTaggedRecord(2, "first_2");
    PutTaggedRecord(1, "second_1");
    PutTaggedRecord(2, "second_2");

    ufifo_oldest(fifo_, 2);  // seek to oldest with tag=2
    char out_buf[128] = {};
    TaggedRecord* out = reinterpret_cast<TaggedRecord*>(out_buf);
    ufifo_get(fifo_, out, sizeof(out_buf));
    EXPECT_EQ(2u, out->tag);
    EXPECT_EQ(0, memcmp(out->data, "first_2", 7));
}

TEST_F(TagSoleSingle, NewestByTag) {
    GenerateName("ts_newest");
    ASSERT_EQ(0, CreateFifo(1024));
    PutTaggedRecord(1, "first_1");
    PutTaggedRecord(2, "first_2");
    PutTaggedRecord(1, "second_1");
    PutTaggedRecord(2, "second_2");

    ufifo_newest(fifo_, 1);  // seek to newest with tag=1
    char out_buf[128] = {};
    TaggedRecord* out = reinterpret_cast<TaggedRecord*>(out_buf);
    ufifo_get(fifo_, out, sizeof(out_buf));
    EXPECT_EQ(1u, out->tag);
    EXPECT_EQ(0, memcmp(out->data, "second_1", 8));
}

TEST_F(TagSoleSingle, TagNotFound) {
    GenerateName("ts_notfound");
    ASSERT_EQ(0, CreateFifo(1024));
    PutTaggedRecord(1, "data");
    ufifo_oldest(fifo_, 999);  // non-existent tag
    // Should still be able to get data (oldest moves to end if not found)
    char out_buf[128] = {};
    unsigned int ret = ufifo_get(fifo_, out_buf, sizeof(out_buf));
    // Behavior depends on implementation - just verify no crash
    (void)ret;
}

TEST_F(TagSoleSingle, MultiTagMixed) {
    GenerateName("ts_multi");
    ASSERT_EQ(0, CreateFifo(2048));
    for (int i = 0; i < 10; i++) {
        char content[16];
        snprintf(content, sizeof(content), "tag%d_%d", i % 3, i);
        PutTaggedRecord(i % 3, content);
    }
    // Filter tag=0: should get items 0, 3, 6, 9
    int count = 0;
    while (ufifo_len(fifo_)) {
        ufifo_oldest(fifo_, 0);
        char out_buf[128] = {};
        TaggedRecord* out = reinterpret_cast<TaggedRecord*>(out_buf);
        unsigned int ret = ufifo_get(fifo_, out, sizeof(out_buf));
        if (ret == 0) break;
        if (out->tag == 0) count++;
        else break;
    }
    EXPECT_GT(count, 0);
}

TEST_F(TagSoleSingle, FifoFullEmpty) {
    GenerateName("ts_fullmt");
    ASSERT_EQ(0, CreateFifo(128));
    char out_buf[64] = {};
    EXPECT_EQ(0u, ufifo_get(fifo_, out_buf, sizeof(out_buf)));

    int count = 0;
    while (true) {
        char buf[64];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = 4;
        rec->tag = 1;
        memset(rec->data, 'x', 4);
        if (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0) break;
        count++;
    }
    EXPECT_GT(count, 0);
}

TEST_F(TagSoleSingle, LargeDataThroughput) {
    GenerateName("ts_throughput");
    ASSERT_EQ(0, CreateFifo(4096));
    for (int i = 0; i < 500; i++) {
        char buf[32];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = sizeof(int);
        rec->tag = i % 5;
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size);
        char out_buf[32] = {};
        ufifo_get(fifo_, out_buf, sizeof(out_buf));
    }
}

// 6.2 SPSC
class TagSoleSPSC : public TagFixture {};

TEST_F(TagSoleSPSC, Basic) {
    GenerateName("ts_spsc");
    ASSERT_EQ(0, CreateFifo(2048, UFIFO_LOCK_THREAD));
    const int N = 100;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 3;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

TEST_F(TagSoleSPSC, Boundary) {
    GenerateName("ts_spsc_bnd");
    ASSERT_EQ(0, CreateFifo(256, UFIFO_LOCK_THREAD));
    std::thread producer([&]() {
        for (int i = 0; i < 20; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 2;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < 20) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(20, count);
}

TEST_F(TagSoleSPSC, Stress) {
    GenerateName("ts_spsc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int N = 3000;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 5;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

// 6.3 SPMC
class TagSoleSPMC : public TagFixture {};

TEST_F(TagSoleSPMC, Basic) {
    GenerateName("ts_spmc");
    ASSERT_EQ(0, CreateFifo(2048, UFIFO_LOCK_THREAD));
    const int N = 100;
    std::atomic<int> consumed{0};
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 3;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    auto consumer_fn = [&]() {
        while (consumed < N) {
            char out_buf[32];
            if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
            else std::this_thread::yield();
        }
    };
    std::thread c1(consumer_fn), c2(consumer_fn);
    producer.join(); c1.join(); c2.join();
    EXPECT_EQ(N, consumed.load());
}

TEST_F(TagSoleSPMC, Boundary) {
    GenerateName("ts_spmc_bnd");
    ASSERT_EQ(0, CreateFifo(256, UFIFO_LOCK_THREAD));
    char buf[32];
    TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
    rec->size = 4; rec->tag = 1;
    memset(rec->data, 'x', 4);
    ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size);

    std::atomic<int> got{0};
    auto fn = [&]() {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) got++;
    };
    std::thread c1(fn), c2(fn);
    c1.join(); c2.join();
    EXPECT_EQ(1, got.load());
}

TEST_F(TagSoleSPMC, Stress) {
    GenerateName("ts_spmc_str");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int N = 1000;
    std::atomic<int> consumed{0};
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 3;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    std::vector<std::thread> consumers;
    for (int c = 0; c < 4; c++) {
        consumers.emplace_back([&]() {
            while (consumed < N) {
                char out_buf[32];
                if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
                else std::this_thread::yield();
            }
        });
    }
    producer.join();
    for (auto& t : consumers) t.join();
    EXPECT_EQ(N, consumed.load());
}

// 6.4 MPSC
class TagSoleMPSC : public TagFixture {};

TEST_F(TagSoleMPSC, Basic) {
    GenerateName("ts_mpsc");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int PER = 50, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;  // each producer uses its own tag
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

TEST_F(TagSoleMPSC, Boundary) {
    GenerateName("ts_mpsc_bnd");
    ASSERT_EQ(0, CreateFifo(128, UFIFO_LOCK_THREAD));
    std::atomic<int> success{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 4; p++) {
        producers.emplace_back([&, p]() {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = 4; rec->tag = p;
            if (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) > 0) success++;
        });
    }
    for (auto& t : producers) t.join();
    EXPECT_GE(success.load(), 1);
}

TEST_F(TagSoleMPSC, Stress) {
    GenerateName("ts_mpsc_str");
    ASSERT_EQ(0, CreateFifo(8192, UFIFO_LOCK_THREAD));
    const int PER = 300, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

// 6.5 MPMC
class TagSoleMPMC : public TagFixture {};

TEST_F(TagSoleMPMC, Basic) {
    GenerateName("ts_mpmc");
    ASSERT_EQ(0, CreateFifo(4096, UFIFO_LOCK_THREAD));
    const int TOTAL = 200;
    std::atomic<int> consumed{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 2; p++) {
        threads.emplace_back([&, p]() {
            for (int i = 0; i < TOTAL / 2; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    for (int c = 0; c < 2; c++) {
        threads.emplace_back([&]() {
            while (consumed < TOTAL) {
                char out_buf[32];
                if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
                else std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL, consumed.load());
}

TEST_F(TagSoleMPMC, Boundary) {
    GenerateName("ts_mpmc_bnd");
    ASSERT_EQ(0, CreateFifo(128, UFIFO_LOCK_THREAD));
    std::atomic<int> produced{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 2; p++) {
        threads.emplace_back([&, p]() {
            for (int i = 0; i < 5; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = 4; rec->tag = p;
                if (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) > 0) produced++;
                std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    int consumed = 0;
    char out_buf[32];
    while (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
    EXPECT_EQ(produced.load(), consumed);
}

TEST_F(TagSoleMPMC, Stress) {
    GenerateName("ts_mpmc_str");
    ASSERT_EQ(0, CreateFifo(8192, UFIFO_LOCK_THREAD));
    const int TOTAL = 1000;
    std::atomic<int> consumed{0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 4; p++) {
        threads.emplace_back([&, p]() {
            for (int i = 0; i < TOTAL / 4; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    for (int c = 0; c < 4; c++) {
        threads.emplace_back([&]() {
            while (consumed < TOTAL) {
                char out_buf[32];
                if (ufifo_get(fifo_, out_buf, sizeof(out_buf)) > 0) consumed++;
                else std::this_thread::yield();
            }
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL, consumed.load());
}

// =============================================================================
// Part 7: Tag + SHARED
// =============================================================================

class TagSharedFixture : public MultiUserFixture {
protected:
    int CreateProducer(unsigned int size, unsigned int max_users = 10) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_THREAD;
        init.alloc.data_mode = UFIFO_DATA_SHARED;
        init.alloc.max_users = max_users;
        init.hook.recsize = tagged_recsize;
        init.hook.rectag = tagged_rectag;
        ufifo_t* fifo = nullptr;
        int ret = ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo);
        if (ret == 0) fifos_.push_back(fifo);
        return ret;
    }

    int AttachTagConsumer(ufifo_t** handle) {
        ufifo_hook_t hook = {};
        hook.recsize = tagged_recsize;
        hook.rectag = tagged_rectag;
        return AttachConsumer(handle, hook);
    }

    void PutTaggedRecord(unsigned int tag, const char* content) {
        char buf[256];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = strlen(content) + 1;
        rec->tag = tag;
        memcpy(rec->data, content, rec->size);
        ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size);
    }
};

// 7.1 Single instance
class TagSharedSingle : public TagSharedFixture {};

TEST_F(TagSharedSingle, AllocAttach) {
    GenerateName("tsh_alloc");
    ASSERT_EQ(0, CreateProducer(512));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);
}

TEST_F(TagSharedSingle, BasicPutGet) {
    GenerateName("tsh_basic");
    ASSERT_EQ(0, CreateProducer(512));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    PutTaggedRecord(1, "hello");
    char out_buf[128] = {};
    TaggedRecord* out = reinterpret_cast<TaggedRecord*>(out_buf);
    EXPECT_GT(ufifo_get(consumer, out, sizeof(out_buf)), 0u);
    EXPECT_EQ(1u, out->tag);
}

TEST_F(TagSharedSingle, OldestByTag) {
    GenerateName("tsh_oldest");
    ASSERT_EQ(0, CreateProducer(1024));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    PutTaggedRecord(1, "first_1");
    PutTaggedRecord(2, "first_2");
    PutTaggedRecord(1, "second_1");

    ufifo_oldest(consumer, 2);
    char out_buf[128] = {};
    TaggedRecord* out = reinterpret_cast<TaggedRecord*>(out_buf);
    ufifo_get(consumer, out, sizeof(out_buf));
    EXPECT_EQ(2u, out->tag);
}

TEST_F(TagSharedSingle, NewestByTag) {
    GenerateName("tsh_newest");
    ASSERT_EQ(0, CreateProducer(1024));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    PutTaggedRecord(1, "first_1");
    PutTaggedRecord(2, "first_2");
    PutTaggedRecord(1, "second_1");

    ufifo_newest(consumer, 1);
    char out_buf[128] = {};
    TaggedRecord* out = reinterpret_cast<TaggedRecord*>(out_buf);
    ufifo_get(consumer, out, sizeof(out_buf));
    EXPECT_EQ(1u, out->tag);
}

TEST_F(TagSharedSingle, TagNotFound) {
    GenerateName("tsh_notfound");
    ASSERT_EQ(0, CreateProducer(1024));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    PutTaggedRecord(1, "data");
    ufifo_oldest(consumer, 999);
    char out_buf[128] = {};
    unsigned int ret = ufifo_get(consumer, out_buf, sizeof(out_buf));
    (void)ret;  // no crash is sufficient
}

TEST_F(TagSharedSingle, FifoFullEmpty) {
    GenerateName("tsh_fullmt");
    ASSERT_EQ(0, CreateProducer(128));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    char out_buf[64] = {};
    EXPECT_EQ(0u, ufifo_get(consumer, out_buf, sizeof(out_buf)));
    int count = 0;
    while (true) {
        char buf[32];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = 4; rec->tag = 1;
        if (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0) break;
        count++;
    }
    EXPECT_GT(count, 0);
}

TEST_F(TagSharedSingle, LargeDataThroughput) {
    GenerateName("tsh_throughput");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    for (int i = 0; i < 500; i++) {
        char buf[32];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = sizeof(int);
        rec->tag = i % 5;
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size);
        char out_buf[32] = {};
        ufifo_get(consumer, out_buf, sizeof(out_buf));
    }
}

// 7.2 SPSC
class TagSharedSPSC : public TagSharedFixture {};

TEST_F(TagSharedSPSC, Basic) {
    GenerateName("tsh_spsc");
    ASSERT_EQ(0, CreateProducer(2048));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    const int N = 100;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 3;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

TEST_F(TagSharedSPSC, Boundary) {
    GenerateName("tsh_spsc_bnd");
    ASSERT_EQ(0, CreateProducer(256));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    std::thread producer([&]() {
        for (int i = 0; i < 20; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 2;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
        }
    });
    int count = 0;
    while (count < 20) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(20, count);
}

TEST_F(TagSharedSPSC, Stress) {
    GenerateName("tsh_spsc_str");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    const int N = 3000;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 5;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
            // Advance producer's out so min(all_outs) moves
            char discard[32];
            ufifo_get(fifos_[0], discard, sizeof(discard));
        }
    });
    int count = 0;
    while (count < N) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    producer.join();
    EXPECT_EQ(N, count);
}

// 7.3 SPMC (broadcast + tag filter)
class TagSharedSPMC : public TagSharedFixture {};

TEST_F(TagSharedSPMC, Broadcast) {
    GenerateName("tsh_spmc");
    ASSERT_EQ(0, CreateProducer(2048));
    const int NC = 3;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachTagConsumer(&c));
        fifos_.push_back(c);
    }

    const int N = 50;
    for (int i = 0; i < N; i++) {
        char buf[32];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = sizeof(int);
        rec->tag = i % 3;
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size);
    }

    for (auto& c : consumers) {
        int count = 0;
        char out_buf[32];
        while (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
        EXPECT_EQ(N, count);
    }
}

TEST_F(TagSharedSPMC, ConsumerIndependence) {
    GenerateName("tsh_spmc_ind");
    ASSERT_EQ(0, CreateProducer(2048));
    ufifo_t *c1 = nullptr, *c2 = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&c1));
    ASSERT_EQ(0, AttachTagConsumer(&c2));
    fifos_.push_back(c1);
    fifos_.push_back(c2);

    for (int i = 0; i < 10; i++) {
        char buf[32];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->size = sizeof(int);
        rec->tag = i % 2;
        memcpy(rec->data, &i, sizeof(i));
        ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size);
    }

    // c1 reads 5 items, c2 reads all
    for (int i = 0; i < 5; i++) {
        char out_buf[32];
        ufifo_get(c1, out_buf, sizeof(out_buf));
    }
    int c2_count = 0;
    char out_buf[32];
    while (ufifo_get(c2, out_buf, sizeof(out_buf)) > 0) c2_count++;
    EXPECT_EQ(10, c2_count);
    int c1_count = 0;
    while (ufifo_get(c1, out_buf, sizeof(out_buf)) > 0) c1_count++;
    EXPECT_EQ(5, c1_count);
}

TEST_F(TagSharedSPMC, Stress) {
    GenerateName("tsh_spmc_str");
    ASSERT_EQ(0, CreateProducer(4096));
    const int NC = 4;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachTagConsumer(&c));
        fifos_.push_back(c);
    }

    const int N = 300;
    std::thread producer([&]() {
        for (int i = 0; i < N; i++) {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = sizeof(int);
            rec->tag = i % 5;
            memcpy(rec->data, &i, sizeof(i));
            while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                std::this_thread::yield();
            // Advance producer's out so min(all_outs) moves
            char discard[32];
            ufifo_get(fifos_[0], discard, sizeof(discard));
        }
    });
    std::vector<std::thread> consumer_threads;
    std::atomic<int> total{0};
    for (auto& c : consumers) {
        consumer_threads.emplace_back([&, c]() {
            int count = 0;
            while (count < N) {
                char out_buf[32];
                if (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
                else std::this_thread::yield();
            }
            total += count;
        });
    }
    producer.join();
    for (auto& t : consumer_threads) t.join();
    EXPECT_EQ(N * NC, total.load());
}

// 7.4 MPSC
class TagSharedMPSC : public TagSharedFixture {};

TEST_F(TagSharedMPSC, Basic) {
    GenerateName("tsh_mpsc");
    ASSERT_EQ(0, CreateProducer(4096));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    const int PER = 50, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

TEST_F(TagSharedMPSC, Boundary) {
    GenerateName("tsh_mpsc_bnd");
    ASSERT_EQ(0, CreateProducer(128));
    std::atomic<int> success{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 4; p++) {
        producers.emplace_back([&, p]() {
            char buf[32];
            TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
            rec->size = 4; rec->tag = p;
            if (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) > 0) success++;
        });
    }
    for (auto& t : producers) t.join();
    EXPECT_GE(success.load(), 1);
}

TEST_F(TagSharedMPSC, Stress) {
    GenerateName("tsh_mpsc_str");
    ASSERT_EQ(0, CreateProducer(8192));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    const int PER = 300, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> producers;
    for (int p = 0; p < NP; p++) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
                // Advance producer's out so min(all_outs) moves
                char discard[32];
                ufifo_get(fifos_[0], discard, sizeof(discard));
            }
        });
    }
    int count = 0;
    while (count < TOTAL) {
        char out_buf[32];
        if (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) count++;
        else std::this_thread::yield();
    }
    for (auto& t : producers) t.join();
    EXPECT_EQ(TOTAL, count);
}

// 7.5 MPMC
class TagSharedMPMC : public TagSharedFixture {};

TEST_F(TagSharedMPMC, BroadcastConcurrent) {
    GenerateName("tsh_mpmc");
    ASSERT_EQ(0, CreateProducer(4096));
    const int NC = 2;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachTagConsumer(&c));
        fifos_.push_back(c);
    }

    const int PER = 50, NP = 2, TOTAL = PER * NP;
    std::vector<std::thread> threads;
    for (int p = 0; p < NP; p++) {
        threads.emplace_back([&, p]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
            }
        });
    }
    std::atomic<int> total{0};
    for (auto& c : consumers) {
        threads.emplace_back([&, c]() {
            int count = 0;
            while (count < TOTAL) {
                char out_buf[32];
                if (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
                else std::this_thread::yield();
            }
            total += count;
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL * NC, total.load());
}

TEST_F(TagSharedMPMC, Boundary) {
    GenerateName("tsh_mpmc_bnd");
    ASSERT_EQ(0, CreateProducer(128));
    ufifo_t* consumer = nullptr;
    ASSERT_EQ(0, AttachTagConsumer(&consumer));
    fifos_.push_back(consumer);

    std::atomic<int> produced{0};
    std::vector<std::thread> producers;
    for (int p = 0; p < 2; p++) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < 5; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = 4; rec->tag = p;
                if (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) > 0) produced++;
                std::this_thread::yield();
            }
        });
    }
    for (auto& t : producers) t.join();
    int consumed = 0;
    char out_buf[32];
    while (ufifo_get(consumer, out_buf, sizeof(out_buf)) > 0) consumed++;
    EXPECT_EQ(produced.load(), consumed);
}

TEST_F(TagSharedMPMC, Stress) {
    GenerateName("tsh_mpmc_str");
    ASSERT_EQ(0, CreateProducer(8192));
    const int NC = 3;
    std::vector<ufifo_t*> consumers(NC);
    for (auto& c : consumers) {
        ASSERT_EQ(0, AttachTagConsumer(&c));
        fifos_.push_back(c);
    }

    const int PER = 150, NP = 4, TOTAL = PER * NP;
    std::vector<std::thread> threads;
    for (int p = 0; p < NP; p++) {
        threads.emplace_back([&, p]() {
            for (int i = 0; i < PER; i++) {
                char buf[32];
                TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
                rec->size = sizeof(int);
                rec->tag = p;
                memcpy(rec->data, &i, sizeof(i));
                while (ufifo_put(fifos_[0], rec, sizeof(TaggedRecord) + rec->size) == 0)
                    std::this_thread::yield();
                // Advance producer's out so min(all_outs) moves
                char discard[32];
                ufifo_get(fifos_[0], discard, sizeof(discard));
            }
        });
    }
    std::atomic<int> total{0};
    for (auto& c : consumers) {
        threads.emplace_back([&, c]() {
            int count = 0;
            while (count < TOTAL) {
                char out_buf[32];
                if (ufifo_get(c, out_buf, sizeof(out_buf)) > 0) count++;
                else std::this_thread::yield();
            }
            total += count;
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(TOTAL * NC, total.load());
}

// =============================================================================
// Part 8: Edge Cases
// =============================================================================

class EdgeCaseTest : public BytestreamFixture {};

TEST_F(EdgeCaseTest, AllocForceOverwrite) {
    GenerateName("ec_force");
    ASSERT_EQ(0, CreateFifo(256));
    int val = 99;
    ufifo_put(fifo_, &val, sizeof(val));
    ufifo_destroy(fifo_);
    fifo_ = nullptr;

    // Re-create with force=1 should succeed and overwrite
    ASSERT_EQ(0, CreateFifo(128));
    EXPECT_EQ(0u, ufifo_len(fifo_));
}

TEST_F(EdgeCaseTest, AllocNoForceReuse) {
    GenerateName("ec_nforce");
    // First alloc
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));
    int val = 42;
    ufifo_put(fifo_, &val, sizeof(val));
    ufifo_destroy(fifo_);
    fifo_ = nullptr;

    // Re-open with force=0 should reuse
    init.alloc.force = 0;
    int ret = ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_);
    if (ret == 0) {
        // Reuse means data might still be there
        EXPECT_NE(nullptr, fifo_);
    }
}

TEST_F(EdgeCaseTest, CrossProcessSharing) {
    GenerateName("ec_fork");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));

    pid_t pid = fork();
    if (pid == 0) {
        // Child: inherited fifo handle, read data
        int out = 0;
        int attempts = 0;
        while (ufifo_get(fifo_, &out, sizeof(out)) == 0 && attempts < 1000) {
            usleep(1000);
            attempts++;
        }
        _exit(out == 12345 ? 0 : 1);
    } else {
        ASSERT_GT(pid, 0);
        usleep(5000);
        int val = 12345;
        ufifo_put(fifo_, &val, sizeof(val));

        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(0, WEXITSTATUS(status));
    }
}

TEST_F(EdgeCaseTest, ProcessLockCrashRecovery) {
    GenerateName("ec_crash");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));

    pid_t pid = fork();
    if (pid == 0) {
        // Child: put data then crash without cleanup
        int val = 999;
        ufifo_put(fifo_, &val, sizeof(val));
        _exit(0);  // exit without ufifo_destroy
    } else {
        ASSERT_GT(pid, 0);
        int status;
        waitpid(pid, &status, 0);

        // Parent should still be able to use the fifo (robust mutex)
        int out = 0;
        unsigned int ret = ufifo_get(fifo_, &out, sizeof(out));
        if (ret > 0) {
            EXPECT_EQ(999, out);
        }
    }
}

TEST_F(EdgeCaseTest, SharedModeUserLimit) {
    GenerateName("ec_usrlmt");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;  // producer + 1 consumer
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &init, &fifo_));

    // First attach should succeed
    ufifo_t* c1 = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(fifo_name_.c_str()), &attach, &c1));

    // Second attach should fail (exceeds max_users)
    ufifo_t* c2 = nullptr;
    int ret = ufifo_open(const_cast<char*>(fifo_name_.c_str()), &attach, &c2);
    EXPECT_NE(0, ret);

    if (c1) ufifo_destroy(c1);
    if (c2) ufifo_destroy(c2);
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
