#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

extern "C" {
#include "ufifo_internal.h"
}

namespace {

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

} // namespace
