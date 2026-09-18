#include <cerrno>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <dirent.h>
#include <string>
#include <sys/mman.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

extern "C" {
#include "ufifo_internal.h"
}

namespace {

std::string WaitTestName(const char *prefix)
{
    static std::atomic<unsigned int> sequence{ 0 };
    return std::string(prefix) + "_" + std::to_string(getpid()) + "_" + std::to_string(sequence++);
}

ufifo_t *OpenWaitTestFifo(const char *prefix, size_t size)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = size;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    const std::string name = WaitTestName(prefix);
    EXPECT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    return fifo;
}

void WaitUntilArmed(const uint32_t *wait_word)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while ((__atomic_load_n(wait_word, __ATOMIC_ACQUIRE) & 1U) == 0 &&
           std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    ASSERT_EQ(1U, __atomic_load_n(wait_word, __ATOMIC_ACQUIRE) & 1U);
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

timespec DeadlineAfterMilliseconds(long milliseconds)
{
    timespec deadline = {};
    EXPECT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &deadline));
    deadline.tv_sec += milliseconds / 1000;
    deadline.tv_nsec += (milliseconds % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    return deadline;
}

TEST(UfifoWaitWordTest, ArmAndNotifyAdvanceOneEpoch)
{
    uint32_t wait_word = 0;

    EXPECT_EQ(1u, __ufifo_wait_arm(&wait_word));
    EXPECT_EQ(1u, wait_word);

    __ufifo_wait_notify(&wait_word);
    EXPECT_EQ(2u, wait_word);

    __ufifo_wait_notify(&wait_word);
    EXPECT_EQ(2u, wait_word);
}

TEST(UfifoWaitWordTest, TimedWaitReportsTimeout)
{
    uint32_t wait_word = 0;
    const uint32_t expected = __ufifo_wait_arm(&wait_word);
    const timespec deadline = DeadlineAfterMilliseconds(20);

    EXPECT_EQ(-ETIMEDOUT, __ufifo_futex_wait(&wait_word, expected, &deadline));
    EXPECT_EQ(expected, wait_word);
}

TEST(UfifoWaitWordTest, NotifyWakesProcessSharedWaiter)
{
    auto *wait_word = static_cast<uint32_t *>(
        mmap(nullptr, sizeof(uint32_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    ASSERT_NE(MAP_FAILED, wait_word);
    *wait_word = 0;

    int ready_pipe[2] = {};
    ASSERT_EQ(0, pipe(ready_pipe));

    const pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        close(ready_pipe[0]);
        const uint32_t expected = __ufifo_wait_arm(wait_word);
        const char ready = 'R';
        if (write(ready_pipe[1], &ready, sizeof(ready)) != sizeof(ready))
            _exit(EXIT_FAILURE);
        const timespec deadline = DeadlineAfterMilliseconds(2000);
        _exit(__ufifo_futex_wait(wait_word, expected, &deadline) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    close(ready_pipe[1]);
    char ready = 0;
    ASSERT_EQ(1, read(ready_pipe[0], &ready, sizeof(ready)));
    EXPECT_EQ('R', ready);

    __ufifo_wait_notify(wait_word);

    int status = 0;
    ASSERT_EQ(child, waitpid(child, &status, 0));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));
    EXPECT_EQ(2u, *wait_word);

    close(ready_pipe[0]);
    EXPECT_EQ(0, munmap(wait_word, sizeof(*wait_word)));
}

TEST(UfifoWaitIntegrationTest, PutWakesBlockedReader)
{
    ufifo_t *fifo = OpenWaitTestFifo("wait_reader", 64);
    ASSERT_NE(nullptr, fifo);

    char received = 0;
    std::thread reader([&] { EXPECT_EQ(1u, ufifo_get_block(fifo, &received, 1)); });
    WaitUntilArmed(&__ufifo_rx_ctrl(fifo)->rx_wait_word);

    const char sent = 'x';
    EXPECT_EQ(1u, ufifo_put(fifo, const_cast<char *>(&sent), 1));
    reader.join();

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
    WaitUntilArmed(&fifo->ctrl->tx_wait_word);

    char received = 0;
    EXPECT_EQ(1u, ufifo_get(fifo, &received, 1));
    writer.join();

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, TimedOutArmIsClearedByNextPublish)
{
    ufifo_t *fifo = OpenWaitTestFifo("wait_timeout", 64);
    ASSERT_NE(nullptr, fifo);

    char received = 0;
    errno = 0;
    EXPECT_EQ(0u, ufifo_get_timeout(fifo, &received, 1, 20));
    EXPECT_EQ(ETIMEDOUT, errno);
    EXPECT_EQ(1U, __ufifo_rx_ctrl(fifo)->rx_wait_word & 1U);

    char sent = 'x';
    EXPECT_EQ(1u, ufifo_put(fifo, &sent, 1));
    EXPECT_EQ(0U, __ufifo_rx_ctrl(fifo)->rx_wait_word & 1U);

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST(UfifoWaitIntegrationTest, CoreOpenDoesNotCreateEventFds)
{
    const size_t before = CountOpenEventFds();
    ufifo_t *fifo = OpenWaitTestFifo("wait_no_eventfd", 64);
    ASSERT_NE(nullptr, fifo);

    EXPECT_EQ(before, CountOpenEventFds());

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

} // namespace
