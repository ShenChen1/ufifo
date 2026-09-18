#include "ufifo_test_support.hpp"

TEST_F(EdgeCaseTest, ReaderCloseWakesBlockedWriter)
{
    std::string name = GenerateName("wr_wakeup");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 128;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.force = 1;

    ufifo_t *writer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &writer));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &reader));

    /* Writer also has an out pointer in SHARED mode — keep it moving */
    char data[64];
    memset(data, 0xAA, sizeof(data));
    while (ufifo_put(writer, data, sizeof(data)) > 0) {
        ufifo_skip(writer);
    }
    /* FIFO is now full from reader's perspective (reader.out == 0, in >> 0) */

    /* Writer blocks on put_timeout (3s generous timeout) */
    std::atomic<bool> writer_woke{ false };
    std::thread writer_thread([&]() {
        char buf[1] = { 0x42 };
        ssize_t ret = ufifo_put_timeout(writer, buf, 1, 3000);
        if (ret > 0)
            writer_woke.store(true, std::memory_order_relaxed);
    });

    /* Give the writer time to enter poll() */
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    /* Closing the reader should free capacity and wake the writer */
    ufifo_close(reader);

    writer_thread.join();
    EXPECT_TRUE(writer_woke.load()) << "Writer should have been woken by reader close";

    ufifo_destroy(writer);
}

// Regression: ufifo_reset must wake a blocked writer
TEST_F(EdgeCaseTest, ResetWakesBlockedWriter)
{
    std::string name = GenerateName("wr_wakeup");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 128;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.force = 1;

    ufifo_t *writer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &writer));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &reader));

    /* Fill the buffer (writer keeps its own out moving) */
    char data[64];
    memset(data, 0xBB, sizeof(data));
    while (ufifo_put(writer, data, sizeof(data)) > 0) {
        ufifo_skip(writer);
    }

    /* Writer blocks on put_timeout */
    std::atomic<bool> writer_woke{ false };
    std::thread writer_thread([&]() {
        char buf[1] = { 0x43 };
        ssize_t ret = ufifo_put_timeout(writer, buf, 1, 3000);
        if (ret > 0)
            writer_woke.store(true, std::memory_order_relaxed);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    /* Reset clears all capacity — must wake the writer */
    ufifo_reset(writer);

    writer_thread.join();
    EXPECT_TRUE(writer_woke.load()) << "Writer should have been woken by reset";

    ufifo_close(reader);
    ufifo_destroy(writer);
}

// Regression: dead reader reap must wake a blocked writer
TEST_F(EdgeCaseTest, DeadReaderReapWakesBlockedWriter)
{
    std::string name = GenerateName("wr_wakeup");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.force = 1;

    ufifo_t *writer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &writer));

    /* Fork a child that attaches as a reader then exits without closing */
    pid_t pid = fork();
    if (pid == 0) {
        ufifo_init_t attach = {};
        attach.opt = UFIFO_OPT_ATTACH;
        ufifo_t *reader = nullptr;
        if (ufifo_open(name.c_str(), &attach, &reader) != 0)
            _exit(1);
        /* Exit without ufifo_close — simulates crash */
        _exit(0);
    }
    ASSERT_GT(pid, 0);
    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Dead reader's out pointer is stuck at 0. Fill the buffer so the writer blocks. */
    char data[32];
    memset(data, 0xCC, sizeof(data));
    while (ufifo_put(writer, data, sizeof(data)) > 0) {
        ufifo_skip(writer);
    }

    /*
     * Writer uses put_timeout. The put slow-path will reap the dead reader
     * and call __ufifo_notify_writers. With the fix, the writer should succeed
     * because after reaping, min_out advances and frees capacity.
     */
    char buf[1] = { 0x44 };
    ssize_t ret = ufifo_put_timeout(writer, buf, 1, 3000);
    EXPECT_GT(ret, 0) << "Writer should succeed after dead reader is reaped";

    ufifo_destroy(writer);
}

// Regression: test lock-free lost wakeup bug
TEST_F(EdgeCaseTest, LockFreeLostWakeupStress)
{
    std::string name = GenerateName("lf_wakeup_stress");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 1024;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.force = 1;

    ufifo_t *writer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &writer));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &reader));

    const int iterations = 50000;
    std::atomic<int> consumed{ 0 };

    std::thread reader_thread([&]() {
        char buf[1];
        for (int i = 0; i < iterations; i++) {
            // Short timeout to avoid hanging the test suite indefinitely if bug triggers
            if (ufifo_get_timeout(reader, buf, 1, 500) > 0) {
                consumed++;
            } else {
                break; // Lost wakeup or timeout
            }
        }
    });

    for (int i = 0; i < iterations; i++) {
        char data[1] = { 0x42 };
        while (ufifo_put(writer, data, 1) == 0) {
            std::this_thread::yield();
        }
    }

    reader_thread.join();
    EXPECT_EQ(iterations, consumed.load()) << "Lost wakeup occurred during Lock-Free stress test";

    ufifo_close(reader);
    ufifo_destroy(writer);
}

// =============================================================================
// 10. Epoll Tests (parameterized by DataFormat, SHARED mode)
// =============================================================================

// Epoll is designed for SHARED mode multi-consumer scenarios.
// Parameterize by DataFormat to cover BYTESTREAM / RECORD / TAG.
