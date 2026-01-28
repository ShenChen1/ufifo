/**
 * @file ufifo_test.cpp
 * @brief Comprehensive GTest test cases for ufifo library
 *
 * Test categories:
 * 1. API parameter tests (negative tests)
 * 2. Bytestream mode tests
 * 3. Record mode tests
 * 4. Tag mode tests
 * 5. Blocking/timeout tests
 * 6. Lock mode tests
 * 7. Multi-instance and concurrency tests (SPSC/SPMC/MPSC/MPMC)
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
// Test Fixtures
// =============================================================================

/**
 * @brief Base fixture for ufifo tests with automatic cleanup
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

    /**
     * @brief Generate unique FIFO name for each test
     */
    std::string GenerateName(const char* prefix) {
        static std::atomic<int> counter{0};
        fifo_name_ = std::string(prefix) + "_" + std::to_string(counter++) +
                     "_" + std::to_string(getpid());
        return fifo_name_;
    }

    /**
     * @brief Create a basic bytestream FIFO
     */
    int CreateBytestream(unsigned int size, ufifo_lock_e lock = UFIFO_LOCK_MUTEX) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.lock = lock;
        init.alloc.size = size;
        init.alloc.force = 1;
        return ufifo_open(const_cast<char*>(GenerateName("bytestream").c_str()),
                          &init, &fifo_);
    }
};

// =============================================================================
// 1. API Parameter Tests (Negative Tests)
// =============================================================================

class UfifoApiTest : public UfifoTestBase {};

TEST_F(UfifoApiTest, OpenWithNullName) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_MUTEX;
    init.alloc.size = 64;

    int ret = ufifo_open(nullptr, &init, &fifo_);
    EXPECT_EQ(ret, -EINVAL) << "Should return -EINVAL when name is NULL";
}

TEST_F(UfifoApiTest, OpenWithNullInit) {
    int ret = ufifo_open(const_cast<char*>("test_null_init"), nullptr, &fifo_);
    EXPECT_EQ(ret, -EINVAL) << "Should return -EINVAL when init is NULL";
}

TEST_F(UfifoApiTest, OpenWithInvalidOpt) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_MAX;  // Invalid
    init.lock = UFIFO_LOCK_MUTEX;
    init.alloc.size = 64;

    int ret = ufifo_open(const_cast<char*>(GenerateName("invalid_opt").c_str()),
                         &init, &fifo_);
    EXPECT_EQ(ret, -EINVAL) << "Should return -EINVAL when opt >= UFIFO_OPT_MAX";
}

TEST_F(UfifoApiTest, OpenWithInvalidLock) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_MAX;  // Invalid
    init.alloc.size = 64;

    int ret = ufifo_open(const_cast<char*>(GenerateName("invalid_lock").c_str()),
                         &init, &fifo_);
    EXPECT_EQ(ret, -EINVAL) << "Should return -EINVAL when lock >= UFIFO_LOCK_MAX";
}

TEST_F(UfifoApiTest, OpenWithZeroSize) {
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_MUTEX;
    init.alloc.size = 0;  // Invalid
    init.alloc.force = 1;

    int ret = ufifo_open(const_cast<char*>(GenerateName("zero_size").c_str()),
                         &init, &fifo_);
    EXPECT_EQ(ret, -EINVAL) << "Should return -EINVAL when size is 0";
}

// =============================================================================
// 2. Bytestream Mode Tests
// =============================================================================

class UfifoBytestreamTest : public UfifoTestBase {};

TEST_F(UfifoBytestreamTest, BasicPutGet) {
    ASSERT_EQ(0, CreateBytestream(64));

    const char* data = "hello";
    unsigned int put_len = ufifo_put(fifo_, const_cast<char*>(data), 5);
    EXPECT_EQ(put_len, 5u) << "Should put 5 bytes";

    char buf[16] = {};
    unsigned int get_len = ufifo_get(fifo_, buf, sizeof(buf));
    EXPECT_EQ(get_len, 5u) << "Should get 5 bytes";
    EXPECT_STREQ(buf, "hello") << "Data should match";
}

TEST_F(UfifoBytestreamTest, PutGetMultiple) {
    ASSERT_EQ(0, CreateBytestream(128));

    for (int i = 0; i < 10; i++) {
        unsigned int put_len = ufifo_put(fifo_, &i, sizeof(i));
        EXPECT_EQ(put_len, sizeof(i)) << "Should put int at iteration " << i;
    }

    EXPECT_EQ(ufifo_len(fifo_), 10 * sizeof(int));

    for (int i = 0; i < 10; i++) {
        int val = -1;
        unsigned int get_len = ufifo_get(fifo_, &val, sizeof(val));
        EXPECT_EQ(get_len, sizeof(val)) << "Should get int at iteration " << i;
        EXPECT_EQ(val, i) << "Value should match at iteration " << i;
    }
}

TEST_F(UfifoBytestreamTest, FifoFull) {
    ASSERT_EQ(0, CreateBytestream(32));  // Actual size will be 32 (power of 2)

    unsigned int size = ufifo_size(fifo_);
    std::vector<unsigned char> data(size);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<unsigned char>(i);
    }

    // Fill the FIFO
    unsigned int put_len = ufifo_put(fifo_, data.data(), size);
    EXPECT_EQ(put_len, size) << "Should fill entire FIFO";

    // Try to put more - should return 0
    unsigned char extra = 0xFF;
    put_len = ufifo_put(fifo_, &extra, 1);
    EXPECT_EQ(put_len, 0u) << "Should return 0 when FIFO is full";
}

TEST_F(UfifoBytestreamTest, FifoEmpty) {
    ASSERT_EQ(0, CreateBytestream(64));

    char buf[16];
    unsigned int get_len = ufifo_get(fifo_, buf, sizeof(buf));
    EXPECT_EQ(get_len, 0u) << "Should return 0 when FIFO is empty";
}

TEST_F(UfifoBytestreamTest, PeekWithoutConsume) {
    ASSERT_EQ(0, CreateBytestream(64));

    const char* data = "peek_test";
    ufifo_put(fifo_, const_cast<char*>(data), strlen(data));

    char buf1[16] = {};
    unsigned int peek_len = ufifo_peek(fifo_, buf1, sizeof(buf1));
    EXPECT_EQ(peek_len, strlen(data));

    // Peek again - should get same data
    char buf2[16] = {};
    peek_len = ufifo_peek(fifo_, buf2, sizeof(buf2));
    EXPECT_EQ(peek_len, strlen(data));
    EXPECT_STREQ(buf1, buf2) << "Peek should not consume data";

    // Verify len unchanged
    EXPECT_EQ(ufifo_len(fifo_), strlen(data));
}

TEST_F(UfifoBytestreamTest, SkipOperation) {
    ASSERT_EQ(0, CreateBytestream(64));

    unsigned char data[] = {1, 2, 3, 4, 5};
    ufifo_put(fifo_, data, sizeof(data));

    EXPECT_EQ(ufifo_len(fifo_), sizeof(data));

    // Skip first element (1 byte in bytestream mode)
    ufifo_skip(fifo_);
    EXPECT_EQ(ufifo_len(fifo_), sizeof(data) - 1);

    unsigned char val;
    ufifo_get(fifo_, &val, 1);
    EXPECT_EQ(val, 2) << "After skip, should get second element";
}

TEST_F(UfifoBytestreamTest, SizeAndLen) {
    ASSERT_EQ(0, CreateBytestream(64));

    // Size should be power of 2, at least 64
    unsigned int size = ufifo_size(fifo_);
    EXPECT_GE(size, 64u);
    EXPECT_EQ(size & (size - 1), 0u) << "Size should be power of 2";

    EXPECT_EQ(ufifo_len(fifo_), 0u) << "Empty FIFO should have len 0";

    char data[32];
    ufifo_put(fifo_, data, sizeof(data));
    EXPECT_EQ(ufifo_len(fifo_), sizeof(data));
}

TEST_F(UfifoBytestreamTest, Reset) {
    ASSERT_EQ(0, CreateBytestream(64));

    char data[32];
    ufifo_put(fifo_, data, sizeof(data));
    EXPECT_EQ(ufifo_len(fifo_), sizeof(data));

    ufifo_reset(fifo_);
    EXPECT_EQ(ufifo_len(fifo_), 0u) << "After reset, len should be 0";

    // Should be able to put data again
    unsigned int put_len = ufifo_put(fifo_, data, sizeof(data));
    EXPECT_EQ(put_len, sizeof(data));
}

// =============================================================================
// 3. Record Mode Tests
// =============================================================================

// Record structure for tests
struct TestRecord {
    unsigned int size;
    char data[0];
};

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

class UfifoRecordTest : public UfifoTestBase {
protected:
    int CreateRecordFifo(unsigned int size, ufifo_lock_e lock = UFIFO_LOCK_MUTEX) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.lock = lock;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.hook.recsize = test_recsize;
        return ufifo_open(const_cast<char*>(GenerateName("record").c_str()),
                          &init, &fifo_);
    }
};

TEST_F(UfifoRecordTest, VariableLengthRecords) {
    ASSERT_EQ(0, CreateRecordFifo(256));

    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);

    // Put records with varying lengths
    const char* strings[] = {"a", "bb", "ccc", "dddd", "eeeee"};
    for (const char* s : strings) {
        rec->size = strlen(s);
        memcpy(rec->data, s, rec->size);
        unsigned int len = ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);
        EXPECT_EQ(len, sizeof(TestRecord) + rec->size);
    }

    // Read back and verify
    for (const char* s : strings) {
        memset(buf, 0, sizeof(buf));
        unsigned int len = ufifo_get(fifo_, buf, sizeof(buf));
        EXPECT_EQ(len, sizeof(TestRecord) + strlen(s));
        EXPECT_EQ(rec->size, strlen(s));
        EXPECT_EQ(memcmp(rec->data, s, rec->size), 0);
    }
}

TEST_F(UfifoRecordTest, PeekLen) {
    ASSERT_EQ(0, CreateRecordFifo(128));

    char buf[64];
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);

    rec->size = 10;
    memset(rec->data, 'x', rec->size);
    ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);

    unsigned int peek_len = ufifo_peek_len(fifo_);
    EXPECT_EQ(peek_len, sizeof(TestRecord) + 10);
}

TEST_F(UfifoRecordTest, RecordWrapAround) {
    ASSERT_EQ(0, CreateRecordFifo(64));

    char buf[64];  // Must be large enough for sizeof(TestRecord) + 30
    TestRecord* rec = reinterpret_cast<TestRecord*>(buf);

    // Fill and read to move pointers near end
    rec->size = 20;
    memset(rec->data, 'A', rec->size);
    ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);
    ufifo_get(fifo_, buf, sizeof(buf));

    // Now put a record that will wrap around
    rec->size = 30;
    memset(rec->data, 'B', rec->size);
    unsigned int put_len = ufifo_put(fifo_, rec, sizeof(TestRecord) + rec->size);
    EXPECT_EQ(put_len, sizeof(TestRecord) + rec->size);

    // Verify it reads correctly
    memset(buf, 0, sizeof(buf));
    unsigned int get_len = ufifo_get(fifo_, buf, sizeof(buf));
    EXPECT_EQ(get_len, sizeof(TestRecord) + 30);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(rec->data[i], 'B');
    }
}

// =============================================================================
// 4. Tag Mode Tests
// =============================================================================

struct TaggedRecord {
    unsigned int size;
    unsigned int tag;
    char data[0];
};

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

static unsigned int tagged_rectag(unsigned char* p1, unsigned int n1, unsigned char* p2) {
    unsigned int tag;
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

class UfifoTagTest : public UfifoTestBase {
protected:
    int CreateTaggedFifo(unsigned int size) {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.lock = UFIFO_LOCK_MUTEX;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.hook.recsize = tagged_recsize;
        init.hook.rectag = tagged_rectag;
        return ufifo_open(const_cast<char*>(GenerateName("tagged").c_str()),
                          &init, &fifo_);
    }

    void PutTaggedRecord(unsigned int tag, const char* content) {
        char buf[64];
        TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
        rec->tag = tag;
        rec->size = strlen(content);
        memcpy(rec->data, content, rec->size);
        ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size);
    }
};

TEST_F(UfifoTagTest, OldestWithTag) {
    ASSERT_EQ(0, CreateTaggedFifo(512));

    // Put records with different tags
    PutTaggedRecord(1, "first_tag1");
    PutTaggedRecord(2, "first_tag2");
    PutTaggedRecord(1, "second_tag1");
    PutTaggedRecord(2, "second_tag2");

    // Find oldest with tag=2
    int ret = ufifo_oldest(fifo_, 2);
    EXPECT_EQ(ret, 0) << "Should find tag";

    char buf[64] = {};
    TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
    ufifo_get(fifo_, buf, sizeof(buf));
    rec->data[rec->size] = '\0';
    EXPECT_STREQ(rec->data, "first_tag2");
}

TEST_F(UfifoTagTest, NewestWithTag) {
    ASSERT_EQ(0, CreateTaggedFifo(512));

    PutTaggedRecord(1, "first_tag1");
    PutTaggedRecord(2, "first_tag2");
    PutTaggedRecord(1, "second_tag1");
    PutTaggedRecord(2, "second_tag2");

    // Find newest with tag=1
    int ret = ufifo_newest(fifo_, 1);
    EXPECT_EQ(ret, 0);

    char buf[64] = {};
    TaggedRecord* rec = reinterpret_cast<TaggedRecord*>(buf);
    ufifo_get(fifo_, buf, sizeof(buf));
    rec->data[rec->size] = '\0';
    EXPECT_STREQ(rec->data, "second_tag1");
}

TEST_F(UfifoTagTest, TagNotFound) {
    ASSERT_EQ(0, CreateTaggedFifo(256));

    PutTaggedRecord(1, "tag1");
    PutTaggedRecord(2, "tag2");

    int ret = ufifo_oldest(fifo_, 999);  // Non-existent tag
    EXPECT_EQ(ret, -ESPIPE) << "Should return -ESPIPE when tag not found";

    // FIFO should now be empty (all records skipped)
    EXPECT_EQ(ufifo_len(fifo_), 0u);
}

// =============================================================================
// 5. Blocking/Timeout Tests
// =============================================================================

class UfifoBlockingTest : public UfifoTestBase {};

TEST_F(UfifoBlockingTest, GetTimeoutOnEmpty) {
    ASSERT_EQ(0, CreateBytestream(64));

    char buf[16];
    auto start = std::chrono::steady_clock::now();
    unsigned int len = ufifo_get_timeout(fifo_, buf, sizeof(buf), 100);
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(len, 0u) << "Should return 0 on timeout";
    EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 90)
        << "Should wait at least ~100ms";
}

TEST_F(UfifoBlockingTest, PutTimeoutOnFull) {
    ASSERT_EQ(0, CreateBytestream(32));

    unsigned int size = ufifo_size(fifo_);
    std::vector<char> data(size);
    ufifo_put(fifo_, data.data(), size);

    char extra = 'x';
    auto start = std::chrono::steady_clock::now();
    unsigned int len = ufifo_put_timeout(fifo_, &extra, 1, 100);
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(len, 0u) << "Should return 0 on timeout";
    EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 90);
}

TEST_F(UfifoBlockingTest, BlockingPutGet) {
    ASSERT_EQ(0, CreateBytestream(64));

    std::atomic<bool> producer_done{false};
    std::atomic<int> received_value{-1};

    // Consumer thread - blocks waiting for data
    std::thread consumer([&]() {
        int val;
        ufifo_get_block(fifo_, &val, sizeof(val));
        received_value = val;
    });

    // Give consumer time to block
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Producer sends data
    int val = 42;
    ufifo_put(fifo_, &val, sizeof(val));
    producer_done = true;

    consumer.join();
    EXPECT_EQ(received_value, 42);
}

TEST_F(UfifoBlockingTest, PeekTimeoutOnEmpty) {
    ASSERT_EQ(0, CreateBytestream(64));

    char buf[16];
    auto start = std::chrono::steady_clock::now();
    unsigned int len = ufifo_peek_timeout(fifo_, buf, sizeof(buf), 100);
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(len, 0u);
    EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 90);
}

// =============================================================================
// 6. Lock Mode Tests
// =============================================================================

class UfifoLockTest : public UfifoTestBase {};

TEST_F(UfifoLockTest, NoLockMode) {
    ASSERT_EQ(0, CreateBytestream(64, UFIFO_LOCK_NONE));

    const char* data = "nolock";
    unsigned int len = ufifo_put(fifo_, const_cast<char*>(data), strlen(data));
    EXPECT_EQ(len, strlen(data));

    char buf[16] = {};
    len = ufifo_get(fifo_, buf, sizeof(buf));
    EXPECT_STREQ(buf, "nolock");
}

TEST_F(UfifoLockTest, MutexLockMode) {
    ASSERT_EQ(0, CreateBytestream(64, UFIFO_LOCK_MUTEX));

    // Basic operation should work
    int val = 123;
    ufifo_put(fifo_, &val, sizeof(val));

    int out;
    ufifo_get(fifo_, &out, sizeof(out));
    EXPECT_EQ(out, 123);
}

TEST_F(UfifoLockTest, FdLockMode) {
    ASSERT_EQ(0, CreateBytestream(64, UFIFO_LOCK_FDLOCK));

    int val = 456;
    ufifo_put(fifo_, &val, sizeof(val));

    int out;
    ufifo_get(fifo_, &out, sizeof(out));
    EXPECT_EQ(out, 456);
}

// =============================================================================
// 7. Multi-instance and Concurrency Tests
// =============================================================================

class UfifoMultiInstanceTest : public ::testing::Test {
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
};

TEST_F(UfifoMultiInstanceTest, AllocAndAttach) {
    ufifo_t* producer = nullptr;
    ufifo_t* consumer = nullptr;

    // Producer allocates
    ufifo_init_t init_alloc = {};
    init_alloc.opt = UFIFO_OPT_ALLOC;
    init_alloc.lock = UFIFO_LOCK_MUTEX;
    init_alloc.alloc.size = 64;
    init_alloc.alloc.force = 1;

    std::string name = GenerateName("alloc_attach");
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_alloc, &producer));
    fifos_.push_back(producer);

    // Consumer attaches
    ufifo_init_t init_attach = {};
    init_attach.opt = UFIFO_OPT_ATTACH;
    init_attach.lock = UFIFO_LOCK_MUTEX;
    init_attach.attach.shared = 0;

    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_attach, &consumer));
    fifos_.push_back(consumer);

    // Producer puts
    int val = 999;
    ufifo_put(producer, &val, sizeof(val));

    // Consumer gets
    int out;
    unsigned int len = ufifo_get(consumer, &out, sizeof(out));
    EXPECT_EQ(len, sizeof(out));
    EXPECT_EQ(out, 999);
}

TEST_F(UfifoMultiInstanceTest, SharedModeIndependentOut) {
    ufifo_t* producer = nullptr;
    ufifo_t* consumer1 = nullptr;
    ufifo_t* consumer2 = nullptr;

    ufifo_init_t init_alloc = {};
    init_alloc.opt = UFIFO_OPT_ALLOC;
    init_alloc.lock = UFIFO_LOCK_MUTEX;
    init_alloc.alloc.size = 64;
    init_alloc.alloc.force = 1;

    std::string name = GenerateName("shared_mode");
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_alloc, &producer));
    fifos_.push_back(producer);

    // Both consumers attach in shared mode
    ufifo_init_t init_attach = {};
    init_attach.opt = UFIFO_OPT_ATTACH;
    init_attach.lock = UFIFO_LOCK_MUTEX;
    init_attach.attach.shared = 1;

    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_attach, &consumer1));
    fifos_.push_back(consumer1);

    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_attach, &consumer2));
    fifos_.push_back(consumer2);

    // Producer puts
    int val = 777;
    ufifo_put(producer, &val, sizeof(val));

    // Both consumers should be able to read the same data
    int out1, out2;
    EXPECT_EQ(ufifo_get(consumer1, &out1, sizeof(out1)), sizeof(out1));
    EXPECT_EQ(ufifo_get(consumer2, &out2, sizeof(out2)), sizeof(out2));
    EXPECT_EQ(out1, 777);
    EXPECT_EQ(out2, 777);
}

// 7.1 SPSC Tests
class UfifoSPSCTest : public UfifoTestBase {};

TEST_F(UfifoSPSCTest, Basic) {
    ASSERT_EQ(0, CreateBytestream(256));

    const int count = 100;
    std::atomic<bool> done{false};

    std::thread producer([&]() {
        for (int i = 0; i < count; i++) {
            while (ufifo_put(fifo_, &i, sizeof(i)) == 0) {
                std::this_thread::yield();
            }
        }
        done = true;
    });

    std::thread consumer([&]() {
        int expected = 0;
        while (expected < count) {
            int val;
            if (ufifo_get(fifo_, &val, sizeof(val)) > 0) {
                EXPECT_EQ(val, expected) << "SPSC data corruption at " << expected;
                expected++;
            } else {
                std::this_thread::yield();
            }
        }
    });

    producer.join();
    consumer.join();
}

TEST_F(UfifoSPSCTest, LargeData) {
    ASSERT_EQ(0, CreateBytestream(4096));

    const int count = 1000;
    std::vector<int> sent, received;

    std::thread producer([&]() {
        for (int i = 0; i < count; i++) {
            while (ufifo_put(fifo_, &i, sizeof(i)) == 0) {
                std::this_thread::yield();
            }
            sent.push_back(i);
        }
    });

    std::thread consumer([&]() {
        int val;
        while (static_cast<int>(received.size()) < count) {
            if (ufifo_get(fifo_, &val, sizeof(val)) > 0) {
                received.push_back(val);
            } else {
                std::this_thread::yield();
            }
        }
    });

    producer.join();
    consumer.join();

    EXPECT_EQ(sent.size(), received.size());
    EXPECT_EQ(sent, received);
}

TEST_F(UfifoSPSCTest, Boundary) {
    ASSERT_EQ(0, CreateBytestream(64));

    unsigned int size = ufifo_size(fifo_);

    // Fill exactly
    std::vector<char> data(size);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<char>(i);
    }

    unsigned int put = ufifo_put(fifo_, data.data(), size);
    EXPECT_EQ(put, size) << "Should fill exactly";
    EXPECT_EQ(ufifo_len(fifo_), size);

    // Empty exactly
    std::vector<char> out(size);
    unsigned int get = ufifo_get(fifo_, out.data(), size);
    EXPECT_EQ(get, size) << "Should empty exactly";
    EXPECT_EQ(ufifo_len(fifo_), 0u);
    EXPECT_EQ(data, out);
}

// 7.2 SPMC Tests
class UfifoSPMCTest : public ::testing::Test {
protected:
    std::vector<ufifo_t*> fifos_;
    std::string fifo_name_;

    void TearDown() override {
        for (auto* f : fifos_) {
            if (f) ufifo_destroy(f);
        }
        fifos_.clear();
    }

    std::string GenerateName() {
        static std::atomic<int> counter{0};
        fifo_name_ = "spmc_" + std::to_string(counter++) + "_" + std::to_string(getpid());
        return fifo_name_;
    }
};

TEST_F(UfifoSPMCTest, BroadcastSemantics) {
    ufifo_t* producer = nullptr;
    ufifo_t* consumer1 = nullptr;
    ufifo_t* consumer2 = nullptr;

    ufifo_init_t init_alloc = {};
    init_alloc.opt = UFIFO_OPT_ALLOC;
    init_alloc.lock = UFIFO_LOCK_MUTEX;
    init_alloc.alloc.size = 256;
    init_alloc.alloc.force = 1;

    std::string name = GenerateName();
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_alloc, &producer));
    fifos_.push_back(producer);

    ufifo_init_t init_attach = {};
    init_attach.opt = UFIFO_OPT_ATTACH;
    init_attach.lock = UFIFO_LOCK_MUTEX;
    init_attach.attach.shared = 1;

    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_attach, &consumer1));
    fifos_.push_back(consumer1);
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init_attach, &consumer2));
    fifos_.push_back(consumer2);

    // Producer sends multiple values
    for (int i = 0; i < 5; i++) {
        ufifo_put(producer, &i, sizeof(i));
    }

    // Each consumer should receive all values (broadcast)
    std::vector<int> recv1, recv2;
    int val;
    while (ufifo_get(consumer1, &val, sizeof(val)) > 0) {
        recv1.push_back(val);
    }
    while (ufifo_get(consumer2, &val, sizeof(val)) > 0) {
        recv2.push_back(val);
    }

    EXPECT_EQ(recv1.size(), 5u);
    EXPECT_EQ(recv2.size(), 5u);
    EXPECT_EQ(recv1, recv2);
}

// 7.3 MPSC Tests
class UfifoMPSCTest : public UfifoTestBase {};

TEST_F(UfifoMPSCTest, ConcurrentPut) {
    ASSERT_EQ(0, CreateBytestream(4096, UFIFO_LOCK_MUTEX));

    const int num_producers = 4;
    const int items_per_producer = 100;
    std::atomic<int> total_put{0};

    std::vector<std::thread> producers;
    for (int p = 0; p < num_producers; p++) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < items_per_producer; i++) {
                int val = p * 1000 + i;
                while (ufifo_put(fifo_, &val, sizeof(val)) == 0) {
                    std::this_thread::yield();
                }
                total_put++;
            }
        });
    }

    std::set<int> received;
    std::thread consumer([&]() {
        while (static_cast<int>(received.size()) < num_producers * items_per_producer) {
            int val;
            if (ufifo_get(fifo_, &val, sizeof(val)) > 0) {
                received.insert(val);
            } else if (total_put >= num_producers * items_per_producer) {
                break;
            } else {
                std::this_thread::yield();
            }
        }
    });

    for (auto& t : producers) t.join();
    consumer.join();

    EXPECT_EQ(received.size(), static_cast<size_t>(num_producers * items_per_producer));
}

TEST_F(UfifoMPSCTest, DataIntegrity) {
    ASSERT_EQ(0, CreateBytestream(2048, UFIFO_LOCK_MUTEX));

    const int num_producers = 2;
    const int items_per_producer = 50;

    std::vector<std::thread> producers;
    for (int p = 0; p < num_producers; p++) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < items_per_producer; i++) {
                int val = p * 10000 + i;
                while (ufifo_put(fifo_, &val, sizeof(val)) == 0) {
                    std::this_thread::yield();
                }
            }
        });
    }

    std::vector<int> received;
    std::thread consumer([&]() {
        while (static_cast<int>(received.size()) < num_producers * items_per_producer) {
            int val;
            if (ufifo_get(fifo_, &val, sizeof(val)) > 0) {
                received.push_back(val);
            } else {
                std::this_thread::yield();
            }
        }
    });

    for (auto& t : producers) t.join();
    consumer.join();

    // Verify each value is valid (from a known producer)
    for (int val : received) {
        int producer_id = val / 10000;
        int item_id = val % 10000;
        EXPECT_GE(producer_id, 0);
        EXPECT_LT(producer_id, num_producers);
        EXPECT_GE(item_id, 0);
        EXPECT_LT(item_id, items_per_producer);
    }
}

// 7.4 MPMC Tests
class UfifoMPMCTest : public UfifoTestBase {};

TEST_F(UfifoMPMCTest, FullConcurrency) {
    ASSERT_EQ(0, CreateBytestream(4096, UFIFO_LOCK_MUTEX));

    const int num_producers = 2;
    const int num_consumers = 2;
    const int items_per_producer = 100;
    std::atomic<int> produced{0};
    std::atomic<int> consumed{0};

    std::vector<std::thread> threads;

    // Producers
    for (int p = 0; p < num_producers; p++) {
        threads.emplace_back([&]() {
            for (int i = 0; i < items_per_producer; i++) {
                int val = i;
                while (ufifo_put(fifo_, &val, sizeof(val)) == 0) {
                    std::this_thread::yield();
                }
                produced++;
            }
        });
    }

    // Consumers
    for (int c = 0; c < num_consumers; c++) {
        threads.emplace_back([&]() {
            while (consumed < num_producers * items_per_producer) {
                int val;
                if (ufifo_get(fifo_, &val, sizeof(val)) > 0) {
                    consumed++;
                } else {
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    EXPECT_EQ(produced.load(), num_producers * items_per_producer);
    EXPECT_EQ(consumed.load(), num_producers * items_per_producer);
}

// 7.5 Edge Cases
class UfifoEdgeCaseTest : public ::testing::Test {
protected:
    std::vector<ufifo_t*> fifos_;

    void TearDown() override {
        for (auto* f : fifos_) {
            if (f) ufifo_destroy(f);
        }
        fifos_.clear();
    }

    std::string GenerateName(const char* prefix) {
        static std::atomic<int> counter{0};
        return std::string(prefix) + "_" + std::to_string(counter++) +
               "_" + std::to_string(getpid());
    }
};

TEST_F(UfifoEdgeCaseTest, AllocForceOverwrite) {
    ufifo_t* fifo1 = nullptr;
    ufifo_t* fifo2 = nullptr;

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_MUTEX;
    init.alloc.size = 64;
    init.alloc.force = 1;

    std::string name = GenerateName("force_overwrite");

    // First allocation
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init, &fifo1));
    fifos_.push_back(fifo1);

    int val = 123;
    ufifo_put(fifo1, &val, sizeof(val));

    // Force overwrite
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init, &fifo2));
    fifos_.push_back(fifo2);

    // New FIFO should be empty
    EXPECT_EQ(ufifo_len(fifo2), 0u);
}

TEST_F(UfifoEdgeCaseTest, AllocNoForceReuse) {
    ufifo_t* fifo1 = nullptr;
    ufifo_t* fifo2 = nullptr;

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_MUTEX;
    init.alloc.size = 64;
    init.alloc.force = 1;

    std::string name = GenerateName("no_force_reuse");

    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init, &fifo1));
    fifos_.push_back(fifo1);

    int val = 456;
    ufifo_put(fifo1, &val, sizeof(val));

    // Without force, should reuse existing
    init.alloc.force = 0;
    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init, &fifo2));
    fifos_.push_back(fifo2);

    // Should be able to read the data
    int out;
    EXPECT_EQ(ufifo_get(fifo2, &out, sizeof(out)), sizeof(out));
    EXPECT_EQ(out, 456);
}

TEST_F(UfifoEdgeCaseTest, CrossProcessSharing) {
    std::string name = GenerateName("cross_proc");

    ufifo_t* fifo = nullptr;
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.lock = UFIFO_LOCK_FDLOCK;  // FDLOCK for cross-process
    init.alloc.size = 64;
    init.alloc.force = 1;

    ASSERT_EQ(0, ufifo_open(const_cast<char*>(name.c_str()), &init, &fifo));
    fifos_.push_back(fifo);

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        ufifo_t* child_fifo = nullptr;
        ufifo_init_t child_init = {};
        child_init.opt = UFIFO_OPT_ATTACH;
        child_init.lock = UFIFO_LOCK_FDLOCK;
        child_init.attach.shared = 0;

        if (ufifo_open(const_cast<char*>(name.c_str()), &child_init, &child_fifo) == 0) {
            int val;
            // Wait for data
            while (ufifo_get(child_fifo, &val, sizeof(val)) == 0) {
                usleep(1000);
            }
            ufifo_close(child_fifo);
            _exit(val == 12345 ? 0 : 1);
        }
        _exit(2);
    } else {
        // Parent process
        usleep(10000);  // Give child time to attach
        int val = 12345;
        ufifo_put(fifo, &val, sizeof(val));

        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(WEXITSTATUS(status), 0) << "Child should receive correct value";
    }
}

// =============================================================================
// Main
// =============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
