#include "ufifo_test_support.hpp"

#include <linux/futex.h>
#include <sys/syscall.h>

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
    EXPECT_EQ(-EINVAL, ufifo_size(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_len(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_reset(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_skip(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_peek_len(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_dump(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_close(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_destroy(nullptr));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_oldest(nullptr, 0));
    EXPECT_EQ(EINVAL, errno);

    errno = 0;
    EXPECT_EQ(-EINVAL, ufifo_newest(nullptr, 0));
    EXPECT_EQ(EINVAL, errno);

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

TEST_F(UfifoErrnoTest, LengthAndControlResults)
{
    EXPECT_EQ(64, ufifo_size(fifo));
    EXPECT_EQ(0, ufifo_len(fifo));
    EXPECT_EQ(0, ufifo_peek_len(fifo));

    char data[] = { 'A', 'B', 'C' };
    ASSERT_EQ(3, ufifo_put(fifo, data, sizeof(data)));
    EXPECT_EQ(3, ufifo_len(fifo));
    EXPECT_EQ(1, ufifo_peek_len(fifo));
    EXPECT_EQ(1, ufifo_skip(fifo));
    EXPECT_EQ(2, ufifo_len(fifo));
    EXPECT_EQ(0, ufifo_reset(fifo));
    EXPECT_EQ(0, ufifo_len(fifo));
    EXPECT_EQ(0, ufifo_skip(fifo));
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
    EXPECT_EQ(-ETIMEDOUT, ufifo_get_timeout(fifo, &data, 1, 200));
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
