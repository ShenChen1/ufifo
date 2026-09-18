#include "ufifo_test_support.hpp"

#include <linux/futex.h>
#include <sys/syscall.h>

class UfifoReapTest : public ::testing::Test {
  protected:
    std::string name;
    void SetUp() override
    {
        name = GenerateName("reap_test");
    }
    void TearDown() override
    {
        shm_unlink(name.c_str());
    }
};

TEST_F(UfifoReapTest, ReapDeadUserOnRegister)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 1024;
    init.alloc.max_users = 2; // Only 2 slots
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.force = 1;

    ufifo_t *fifo1 = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo1));

    // Slot 0 is taken by fifo1.
    // Now take Slot 1 via a child process that then dies.
    pid_t pid = fork();
    if (pid == 0) {
        ufifo_init_t attach_init = {};
        attach_init.opt = UFIFO_OPT_ATTACH;
        ufifo_t *fifo_child = nullptr;
        if (ufifo_open(name.c_str(), &attach_init, &fifo_child) == 0) {
            _exit(0);
        }
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    // Now try to attach a new one. It should trigger reaping in __ufifo_register because 2 slots were used.
    ufifo_t *fifo2 = nullptr;
    ufifo_init_t attach_init = {};
    attach_init.opt = UFIFO_OPT_ATTACH;

    // This should succeed by reaping the dead child
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach_init, &fifo2));

    ufifo_close(fifo2);
    ufifo_destroy(fifo1);
}

TEST_F(UfifoReapTest, ReapDeadUserOnPut)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64; // Small size to fill quickly
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.force = 1;

    ufifo_t *producer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &producer));

    // Start a reader process that reads one byte then dies.
    pid_t pid = fork();
    if (pid == 0) {
        ufifo_init_t attach_init = {};
        attach_init.opt = UFIFO_OPT_ATTACH;
        ufifo_t *reader = nullptr;
        if (ufifo_open(name.c_str(), &attach_init, &reader) == 0) {
            char b;
            if (ufifo_get_block(reader, &b, 1) == 1) {
                _exit(0);
            }
        }
        _exit(1);
    }

    // Give some time for child to start
    usleep(100000);

    // Write one byte to let the reader finish and exit.
    char data = 'A';
    ASSERT_EQ(1, ufifo_put(producer, &data, 1));

    // In SHARED mode, the producer also has its own 'out' pointer.
    // To ensure the producer doesn't block itself, we keep its 'out' moving.
    ufifo_skip(producer);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    // Now Slot 0 (producer) is at out=1, Slot 1 (dead child) is at out=1.
    // in=1.
    // Fill 63 bytes.
    char large_buf[64];
    memset(large_buf, 'B', sizeof(large_buf));
    ASSERT_EQ(63, ufifo_put(producer, large_buf, 63));

    // After put, in=64.
    // We must also skip the 63 bytes for Slot 0, otherwise Slot 0 itself will be the bottleneck!
    for (int i = 0; i < 63; i++)
        ufifo_skip(producer);

    // Now Slot 0 is at out=64. Slot 1 (dead) is at out=1.
    // in=64. mask=63. size=64.
    // unused_len = 64 - (64 - 1) = 1.
    // Trying to put 2 bytes will now trigger reaping of Slot 1 because it's the ONLY bottleneck.
    ASSERT_EQ(2, ufifo_put(producer, large_buf, 2));

    ufifo_destroy(producer);
}

// =============================================================================
// 12. Errno Unified Tests
// =============================================================================
class UfifoErrnoTest : public ::testing::Test {
  protected:
    std::string name;
    ufifo_t *fifo = nullptr;

    void SetUp() override
    {
        name = GenerateName("errno_test");
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = 64;
        init.alloc.max_users = 1;
        init.alloc.data_mode = UFIFO_DATA_SOLE;
        init.alloc.force = 1;
        ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    }

    void TearDown() override
    {
        if (fifo)
            ufifo_destroy(fifo);
    }
};

TEST_F(UfifoErrnoTest, InvalidHandle)
{
    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_put(nullptr, nullptr, 1));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_get(nullptr, nullptr, 1));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_peek(nullptr, nullptr, 1));
    EXPECT_EQ(EINVAL, errno);
}

TEST_F(UfifoErrnoTest, EmptyAndFull)
{
    char data = 'A';
    errno = 0;
    EXPECT_EQ(-EAGAIN, ufifo_get(fifo, &data, 1));
    EXPECT_EQ(EAGAIN, errno);

    errno = 0;
    EXPECT_EQ(-EAGAIN, ufifo_peek(fifo, &data, 1));
    EXPECT_EQ(EAGAIN, errno);

    for (int i = 0; i < 64; i++) {
        ufifo_put(fifo, &data, 1);
    }

    errno = 0;
    EXPECT_EQ(-EAGAIN, ufifo_put(fifo, &data, 1));
    EXPECT_EQ(EAGAIN, errno);
}

TEST_F(UfifoErrnoTest, Timeout)
{
    char data = 'A';
    errno = 0;
    EXPECT_EQ(-ETIMEDOUT, ufifo_get_timeout(fifo, &data, 1, 10));
    EXPECT_EQ(ETIMEDOUT, errno);

    errno = 0;
    EXPECT_EQ(-ETIMEDOUT, ufifo_peek_timeout(fifo, &data, 1, 10));
    EXPECT_EQ(ETIMEDOUT, errno);

    for (int i = 0; i < 64; i++) {
        ufifo_put(fifo, &data, 1);
    }

    errno = 0;
    EXPECT_EQ(-ETIMEDOUT, ufifo_put_timeout(fifo, &data, 1, 10));
    EXPECT_EQ(ETIMEDOUT, errno);
}

TEST_F(UfifoErrnoTest, LongTimeoutOverflow)
{
    char data = 'A';
    for (int i = 0; i < 64; i++) {
        ufifo_put(fifo, &data, 1);
    }

    std::thread t([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        char b;
        ufifo_get(fifo, &b, 1);
    });

    long huge_timeout = 3000L + (long)INT_MAX; // Triggers clamp to INT_MAX
    errno = 0;
    EXPECT_EQ(1u, ufifo_put_timeout(fifo, &data, 1, huge_timeout));
    t.join();
}

TEST_F(UfifoErrnoTest, StrictTimeoutWithSpuriousWakeup)
{
    char data = 'A';
    uint32_t *wait_word = &__ufifo_rx_ctrl(fifo)->rx_wait_word;

    std::thread t([&]() {
        for (int i = 0; i < 5; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            syscall(SYS_futex, wait_word, FUTEX_WAKE, INT_MAX, nullptr, nullptr, 0);
        }
    });

    auto start = std::chrono::steady_clock::now();

    errno = 0;
    // Timeout is 200 ms.
    EXPECT_EQ(0u, ufifo_get_timeout(fifo, &data, 1, 200));
    EXPECT_EQ(ETIMEDOUT, errno);

    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    t.join();

    // The absolute deadline must survive repeated futex wakeups with no data publication.
    EXPECT_GE(elapsed, 150);
    EXPECT_LT(elapsed, 400);
}

static size_t failing_recput(uint8_t *, size_t, uint8_t *, void *)
{
    return 0; // Fail
}

static size_t failing_recget(uint8_t *, size_t, uint8_t *, void *)
{
    return 0; // Fail
}

static size_t dummy_recsize(uint8_t *, size_t, uint8_t *)
{
    return 10; // Fixed record size
}

TEST_F(UfifoErrnoTest, CustomCallbackFailure)
{
    ufifo_destroy(fifo);
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.max_users = 1;
    init.alloc.force = 1;
    init.hook.recput = failing_recput;
    init.hook.recget = failing_recget;
    init.hook.recsize = dummy_recsize;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    char data[10] = {};
    errno = 0;
    EXPECT_EQ(-EIO, ufifo_put(fifo, data, 10));
    EXPECT_EQ(EIO, errno);

    ufifo_destroy(fifo);
    init.hook.recput = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    EXPECT_EQ(10u, ufifo_put(fifo, data, 10));

    errno = 0;
    EXPECT_EQ(-EIO, ufifo_peek(fifo, data, 10));
    EXPECT_EQ(EIO, errno);

    errno = 0;
    EXPECT_EQ(-EIO, ufifo_get(fifo, data, 10));
    EXPECT_EQ(EIO, errno);
}

TEST_F(UfifoErrnoTest, BufferTooSmall)
{
    ufifo_destroy(fifo);
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.max_users = 1;
    init.alloc.force = 1;
    init.hook.recsize = dummy_recsize;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    char data[10] = {};
    EXPECT_EQ(10u, ufifo_put(fifo, data, 10));

    char small_buf[5];
    errno = 0;
    EXPECT_EQ(-ENOBUFS, ufifo_peek(fifo, small_buf, 5));
    EXPECT_EQ(ENOBUFS, errno);

    errno = 0;
    EXPECT_EQ(-ENOBUFS, ufifo_get(fifo, small_buf, 5));
    EXPECT_EQ(ENOBUFS, errno);
}

// =============================================================================
// Fault Injection Tests
// =============================================================================
