#include "ufifo_test_runtime.hpp"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <gtest/gtest.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" {
#include "ufifo_wait_word.h"
}

namespace {

void InterruptWait(int)
{}

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

} // namespace

TEST(UfifoWaitWordTest, NotifyOnlyAdvancesArmedEpoch)
{
    ufifo_atomic_uint32_t wait_word = 0;

    __ufifo_wait_notify(&wait_word);
    EXPECT_EQ(0u, wait_word);

    EXPECT_EQ(1u, __ufifo_wait_arm(&wait_word));
    EXPECT_EQ(1u, wait_word);
    __ufifo_wait_notify(&wait_word);
    EXPECT_EQ(2u, wait_word);

    __ufifo_wait_notify(&wait_word);
    EXPECT_EQ(2u, wait_word);
}

TEST(UfifoWaitWordTest, TimedWaitReportsTimeout)
{
    ufifo_atomic_uint32_t wait_word = 0;
    const uint32_t expected = __ufifo_wait_arm(&wait_word);
    const timespec deadline = DeadlineAfterMilliseconds(20);

    EXPECT_EQ(-ETIMEDOUT, __ufifo_futex_wait(&wait_word, expected, &deadline));
    EXPECT_EQ(expected, wait_word);
}

TEST(UfifoWaitWordTest, NotifyWakesProcessSharedWaiter)
{
    auto *wait_word = static_cast<ufifo_atomic_uint32_t *>(
        mmap(nullptr, sizeof(ufifo_atomic_uint32_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    ASSERT_NE(MAP_FAILED, wait_word);
    *wait_word = 0;

    TestPipe ready_pipe;
    ASSERT_EQ(0, TestPipe::Create(&ready_pipe));

    const pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ready_pipe.CloseRead();
        const uint32_t expected = __ufifo_wait_arm(wait_word);
        if (ready_pipe.WriteByte('R') != 0)
            _exit(EXIT_FAILURE);
        const timespec deadline = DeadlineAfterMilliseconds(2000);
        _exit(__ufifo_futex_wait(wait_word, expected, &deadline) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    ChildProcess process(child);
    ready_pipe.CloseWrite();
    char ready = 0;
    TestDeadline ready_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, ready_pipe.ReadByteUntil(ready_deadline, &ready));
    EXPECT_EQ('R', ready);

    __ufifo_wait_notify(wait_word);

    int status = 0;
    TestDeadline child_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, process.WaitUntil(child_deadline, &status));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));
    EXPECT_EQ(2u, *wait_word);

    EXPECT_EQ(0, munmap(wait_word, sizeof(*wait_word)));
}

TEST(UfifoWaitWordTest, MultipleArmsShareOneEpoch)
{
    ufifo_atomic_uint32_t word = 40;
    EXPECT_EQ(41U, __ufifo_wait_arm(&word));
    EXPECT_EQ(41U, __ufifo_wait_arm(&word));
    __ufifo_wait_notify(&word);
    EXPECT_EQ(42U, ufifo_atomic_load_acquire(&word));
    EXPECT_EQ(43U, __ufifo_wait_arm(&word));
}

TEST(UfifoWaitWordTest, PublishedEpochPreventsLateSleep)
{
    ufifo_atomic_uint32_t word = 0;
    const uint32_t expected = __ufifo_wait_arm(&word);
    __ufifo_wait_notify(&word);
    const timespec expired = {};
    EXPECT_EQ(0, __ufifo_futex_wait(&word, expected, &expired));
}

TEST(UfifoWaitWordTest, EpochWrapsAndStillRejectsOldExpectedValue)
{
    ufifo_atomic_uint32_t word = UINT32_MAX - 1U;
    const uint32_t expected = __ufifo_wait_arm(&word);
    EXPECT_EQ(UINT32_MAX, expected);
    __ufifo_wait_notify(&word);
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(&word));
    const timespec expired = {};
    EXPECT_EQ(0, __ufifo_futex_wait(&word, expected, &expired));
    EXPECT_EQ(1U, __ufifo_wait_arm(&word));
}

TEST(UfifoWaitWordTest, InvalidDeadlineReportsSpecificError)
{
    ufifo_atomic_uint32_t word = 0;
    const uint32_t expected = __ufifo_wait_arm(&word);
    const timespec invalid = { 0, 1000000000L };
    EXPECT_EQ(-EINVAL, __ufifo_futex_wait(&word, expected, &invalid));
    EXPECT_EQ(expected, ufifo_atomic_load_acquire(&word));
}

TEST(UfifoWaitWordTest, SignalInterruptIsReturnedToCaller)
{
    TestPipe ready;
    TestPipe completed;
    ASSERT_EQ(0, TestPipe::Create(&ready));
    ASSERT_EQ(0, TestPipe::Create(&completed));
    const pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        struct sigaction action = {};
        action.sa_handler = InterruptWait;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR1, &action, nullptr) != 0)
            _exit(EXIT_FAILURE);
        ufifo_atomic_uint32_t word = 0;
        const uint32_t expected = __ufifo_wait_arm(&word);
        const timespec deadline = DeadlineAfterMilliseconds(2000);
        if (ready.WriteByte('R') != 0)
            _exit(EXIT_FAILURE);
        const int result = __ufifo_futex_wait(&word, expected, &deadline);
        completed.WriteByte(result == -EINTR ? 'S' : 'F');
        _exit(result == -EINTR ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    ChildProcess process(child);
    ready.CloseWrite();
    completed.CloseWrite();
    char value = 0;
    TestDeadline ready_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, ready.ReadByteUntil(ready_deadline, &value));
    int read_result = -ETIMEDOUT;
    TestDeadline interrupt_deadline(std::chrono::seconds(2));
    while (read_result == -ETIMEDOUT && !interrupt_deadline.Expired()) {
        ASSERT_EQ(0, kill(child, SIGUSR1));
        TestDeadline retry_deadline(std::chrono::milliseconds(5));
        read_result = completed.ReadByteUntil(retry_deadline, &value);
    }
    EXPECT_EQ(0, read_result);
    EXPECT_EQ('S', value);
    int status = 0;
    TestDeadline exit_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, process.WaitUntil(exit_deadline, &status));
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));
}
