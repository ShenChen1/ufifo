#include "ufifo_test_support.hpp"

#include <dirent.h>

extern "C" {
#include "ufifo_predicate.h"
}

namespace {

ufifo_t *OpenWaitTestFifo(const char *prefix, size_t size, ufifo_lock_e lock = UFIFO_LOCK_THREAD)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = size;
    init.alloc.force = 1;
    init.alloc.lock = lock;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    const std::string name = GenerateName(prefix);
    EXPECT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    return fifo;
}

size_t CountOpenEventFds()
{
    DIR *directory = opendir("/proc/self/fd");
    EXPECT_NE(nullptr, directory);
    if (!directory)
        return 0;

    size_t count = 0;
    while (const dirent *entry = readdir(directory)) {
        if (entry->d_name[0] == '.')
            continue;
        const std::string path = std::string("/proc/self/fd/") + entry->d_name;
        char target[128] = {};
        const ssize_t length = readlink(path.c_str(), target, sizeof(target) - 1);
        if (length > 0 && std::string(target, static_cast<size_t>(length)) == "anon_inode:[eventfd]")
            count++;
    }
    closedir(directory);
    return count;
}

ufifo_init_t MakeCoreOptions(ufifo_lock_e lock, ufifo_data_mode_e mode)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = lock;
    init.alloc.data_mode = mode;
    init.alloc.max_users = 2;
    return init;
}

double ElapsedMilliseconds(const std::chrono::steady_clock::time_point &start,
                           const std::chrono::steady_clock::time_point &end)
{
    return std::chrono::duration<double, std::milli>(end - start).count();
}

enum class SharedCapacityChange { CloseReader, ResetAll };

void CheckSharedCapacityWakesWriter(SharedCapacityChange change)
{
    constexpr size_t kCapacity = 128;
    constexpr long kWriterTimeoutMs = 3000;
    const std::string name = GenerateName("shared_capacity_wakeup");
    ufifo_init_t init = MakeCoreOptions(UFIFO_LOCK_THREAD, UFIFO_DATA_SHARED);
    init.alloc.size = kCapacity;
    ufifo_t *writer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &writer));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &reader));

    // BOTH-role writers must advance their own cursor; the reader holds capacity.
    char data[kCapacity / 2] = {};
    for (size_t offset = 0; offset < kCapacity; offset += sizeof(data)) {
        ASSERT_EQ(sizeof(data), ufifo_put(writer, data, sizeof(data)));
        ASSERT_EQ(1, ufifo_skip(writer));
    }
    ASSERT_EQ(-EAGAIN, ufifo_put(writer, data, 1));

    ssize_t writer_result = -EINPROGRESS;
    std::thread blocked_writer([&] {
        char value = 'x';
        writer_result = ufifo_put_timeout(writer, &value, 1, kWriterTimeoutMs);
    });
    const bool armed = WaitForWaitWordArm(__ufifo_tx_wait_word(writer));
    int publish_result = -ETIMEDOUT;
    if (armed) {
        if (change == SharedCapacityChange::CloseReader) {
            publish_result = ufifo_close(reader);
            if (publish_result == 0)
                reader = nullptr;
        } else {
            publish_result = ufifo_reset(writer);
        }
    }
    blocked_writer.join();

    EXPECT_TRUE(armed);
    EXPECT_EQ(0, publish_result);
    EXPECT_EQ(1, writer_result);
    if (reader != nullptr) {
        EXPECT_EQ(0, ufifo_close(reader));
    }
    EXPECT_EQ(0, ufifo_destroy(writer));
}

} // namespace

TEST(UfifoWaitIntegrationTest, PutWakesBlockedReader)
{
    ufifo_t *fifo = OpenWaitTestFifo("wait_reader", 64);
    ASSERT_NE(nullptr, fifo);

    char received = 0;
    std::thread reader([&] { EXPECT_EQ(1u, ufifo_get_block(fifo, &received, 1)); });
    const bool armed = WaitForWaitWordArm(__ufifo_rx_wait_word(fifo));

    const char sent = 'x';
    EXPECT_EQ(1u, ufifo_put(fifo, const_cast<char *>(&sent), 1));
    reader.join();
    EXPECT_TRUE(armed);

    EXPECT_EQ(sent, received);
    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, GetWakesBlockedWriter)
{
    ufifo_t *fifo = OpenWaitTestFifo("wait_writer", 64);
    ASSERT_NE(nullptr, fifo);

    char fill[64] = {};
    ASSERT_EQ(sizeof(fill), ufifo_put(fifo, fill, sizeof(fill)));

    char pending = 'x';
    std::thread writer([&] { EXPECT_EQ(1u, ufifo_put_block(fifo, &pending, 1)); });
    const bool armed = WaitForWaitWordArm(__ufifo_tx_wait_word(fifo));

    char received = 0;
    EXPECT_EQ(1u, ufifo_get(fifo, &received, 1));
    writer.join();
    EXPECT_TRUE(armed);

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, ArmedWriterUsesStrictSpaceRecheck)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    const std::string name = GenerateName("wait_writer_recheck");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    char data[64] = {};
    ASSERT_EQ(sizeof(data), ufifo_put(fifo, data, sizeof(data)));
    ASSERT_EQ(0U, __ufifo_tx_available_fast(fifo));

    __ufifo_wait_arm(__ufifo_tx_wait_word(fifo));
    ufifo_atomic_store_release(fifo->kfifo.out, 1);
    ASSERT_EQ(1U, ufifo_atomic_load_acquire(__ufifo_tx_wait_word(fifo)) & 1U);
    EXPECT_EQ(1U, __ufifo_tx_available_after_arm(fifo));
    __ufifo_wait_notify(__ufifo_tx_wait_word(fifo));

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, LockFreeGetWakesBlockedWriter)
{
    ufifo_t *fifo = OpenWaitTestFifo("wait_lock_free_writer", 64, UFIFO_LOCK_NONE);
    ASSERT_NE(nullptr, fifo);

    char data[64] = {};
    ASSERT_EQ(sizeof(data), ufifo_put(fifo, data, sizeof(data)));

    std::atomic<ssize_t> writer_result{ -EINPROGRESS };
    char pending = 'x';
    std::thread writer([&] { writer_result.store(ufifo_put_timeout(fifo, &pending, 1, 2000)); });
    const bool armed = WaitForWaitWordArm(__ufifo_tx_wait_word(fifo));

    EXPECT_EQ(1, ufifo_get(fifo, data, 1));
    writer.join();
    EXPECT_TRUE(armed);

    EXPECT_EQ(1, writer_result.load());
    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, TimedOutArmIsClearedByNextPublish)
{
    ufifo_t *fifo = OpenWaitTestFifo("wait_timeout", 64);
    ASSERT_NE(nullptr, fifo);

    char received = 0;
    errno = 0;
    EXPECT_EQ(-ETIMEDOUT, ufifo_get_timeout(fifo, &received, 1, 20));
    EXPECT_EQ(ETIMEDOUT, errno);
    EXPECT_EQ(1U, ufifo_atomic_load_acquire(__ufifo_rx_wait_word(fifo)) & 1U);

    char sent = 'x';
    EXPECT_EQ(1u, ufifo_put(fifo, &sent, 1));
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(__ufifo_rx_wait_word(fifo)) & 1U);

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, NoWaiterPublishLeavesWaitWordsIdle)
{
    ufifo_t *fifo = OpenWaitTestFifo("wait_idle", 64);
    ASSERT_NE(nullptr, fifo);

    char value = 'x';
    ASSERT_EQ(1u, ufifo_put(fifo, &value, 1));
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(__ufifo_rx_wait_word(fifo)));

    ASSERT_EQ(1u, ufifo_get(fifo, &value, 1));
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(__ufifo_tx_wait_word(fifo)));

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, SharedHandlesUseOneReceiveEpoch)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    const std::string name = GenerateName("wait_shared_epoch");
    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &reader));

    EXPECT_EQ(1U, __ufifo_wait_arm(__ufifo_rx_wait_word(owner)));
    EXPECT_EQ(1U, ufifo_atomic_load_acquire(__ufifo_rx_wait_word(reader)));
    __ufifo_wait_notify(__ufifo_rx_wait_word(reader));
    EXPECT_EQ(2U, ufifo_atomic_load_acquire(__ufifo_rx_wait_word(owner)));

    EXPECT_EQ(0, ufifo_close(reader));
    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoWaitIntegrationTest, SharedWriterEpochAdvancesOnlyWithCapacity)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    const std::string name = GenerateName("wait_shared_capacity");
    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &reader));

    char value = 'x';
    ASSERT_EQ(1, ufifo_put(owner, &value, 1));
    const uint32_t armed_tx_epoch = __ufifo_wait_arm(__ufifo_tx_wait_word(owner));
    ASSERT_EQ(1, ufifo_get(owner, &value, 1));
    EXPECT_EQ(armed_tx_epoch, ufifo_atomic_load_acquire(__ufifo_tx_wait_word(owner)));
    ASSERT_EQ(1, ufifo_get(reader, &value, 1));
    EXPECT_EQ(armed_tx_epoch + 1U, ufifo_atomic_load_acquire(__ufifo_tx_wait_word(owner)));

    EXPECT_EQ(0, ufifo_close(reader));
    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoWaitIntegrationTest, CoreOpenDoesNotCreateEventFds)
{
    const size_t before = CountOpenEventFds();
    ufifo_t *fifo = OpenWaitTestFifo("wait_no_eventfd", 64);
    ASSERT_NE(nullptr, fifo);

    EXPECT_EQ(before, CountOpenEventFds());

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST_F(EdgeCaseTest, ReaderCloseWakesBlockedWriter)
{
    CheckSharedCapacityWakesWriter(SharedCapacityChange::CloseReader);
}

TEST_F(EdgeCaseTest, ResetWakesBlockedWriter)
{
    CheckSharedCapacityWakesWriter(SharedCapacityChange::ResetAll);
}

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
    ChildProcess child(pid);
    int status = 0;
    TestDeadline child_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, child.WaitUntil(child_deadline, &status));
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

TEST(UfifoCoreRegressionTest, TimeoutIncludesInitialDataLockWait)
{
    const std::string name = GenerateName("timeout_initial_lock");
    ufifo_init_t init = MakeCoreOptions(UFIFO_LOCK_PROCESS, UFIFO_DATA_SOLE);
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    ASSERT_EQ(0, pthread_mutex_lock(&fifo->ctrl->data_mutex));

    std::atomic<bool> started{ false };
    ssize_t result = 0;
    double elapsed_ms = 0;
    std::thread waiter([&]() {
        char output = 0;
        const auto start = std::chrono::steady_clock::now();
        started.store(true);
        result = ufifo_get_timeout(fifo, &output, sizeof(output), 10);
        elapsed_ms = ElapsedMilliseconds(start, std::chrono::steady_clock::now());
    });
    TestDeadline start_deadline(TEST_PROCESS_TIMEOUT);
    while (!started.load() && !start_deadline.Expired())
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const int unlock_result = pthread_mutex_unlock(&fifo->ctrl->data_mutex);
    waiter.join();
    EXPECT_TRUE(started.load());
    EXPECT_EQ(0, unlock_result);

    EXPECT_EQ(-ETIMEDOUT, result);
    EXPECT_LT(elapsed_ms, 100.0);
    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoCoreRegressionTest, TimeoutIncludesDataLockReacquire)
{
    const std::string name = GenerateName("timeout_relock");
    ufifo_init_t init = MakeCoreOptions(UFIFO_LOCK_PROCESS, UFIFO_DATA_SOLE);
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    ssize_t result = 0;
    double elapsed_ms = 0;
    std::thread waiter([&]() {
        char output = 0;
        const auto start = std::chrono::steady_clock::now();
        result = ufifo_get_timeout(fifo, &output, sizeof(output), 40);
        elapsed_ms = ElapsedMilliseconds(start, std::chrono::steady_clock::now());
    });
    ufifo_atomic_uint32_t *wait_word = __ufifo_rx_wait_word(fifo);
    const bool armed = WaitForWaitWordArm(wait_word);
    int lock_result = EINVAL;
    int unlock_result = EINVAL;
    if (armed) {
        lock_result = pthread_mutex_lock(&fifo->ctrl->data_mutex);
        if (lock_result == 0) {
            __ufifo_wait_notify(wait_word);
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            unlock_result = pthread_mutex_unlock(&fifo->ctrl->data_mutex);
        }
    }
    waiter.join();

    ASSERT_TRUE(armed);
    ASSERT_EQ(0, lock_result);
    ASSERT_EQ(0, unlock_result);
    EXPECT_EQ(-ETIMEDOUT, result);
    EXPECT_LT(elapsed_ms, 100.0);
    EXPECT_EQ(0, ufifo_destroy(fifo));
}
