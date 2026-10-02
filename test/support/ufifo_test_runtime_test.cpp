#include "ufifo_test_support.hpp"

#include <cstdlib>

TEST(UfifoTestRuntimeTest, FirstFailurePreservesFirstError)
{
    FirstFailure failure;

    failure.Record(-EIO);
    failure.Record(-ETIMEDOUT);

    EXPECT_FALSE(failure.Ok());
    EXPECT_EQ(-EIO, failure.Get());
}

TEST(UfifoTestRuntimeTest, StartGateReleasesReadyParticipant)
{
    StartGate gate(1);
    TestDeadline deadline(std::chrono::seconds(1));
    bool released = false;
    std::thread participant([&] { released = gate.ArriveAndWait(deadline); });

    EXPECT_TRUE(gate.Release(deadline));
    participant.join();

    EXPECT_TRUE(released);
}

TEST(UfifoTestRuntimeTest, StartGateTimeoutCancelsLateParticipant)
{
    StartGate gate(2);
    TestDeadline release_deadline(std::chrono::milliseconds(20));

    EXPECT_FALSE(gate.Release(release_deadline));

    TestDeadline participant_deadline(std::chrono::seconds(1));
    EXPECT_FALSE(gate.ArriveAndWait(participant_deadline));
}

TEST(UfifoTestRuntimeTest, PipeTransfersOneByte)
{
    TestPipe pipe;
    ASSERT_EQ(0, TestPipe::Create(&pipe));
    ASSERT_EQ(0, pipe.WriteByte('R'));

    char value = 0;
    TestDeadline deadline(std::chrono::seconds(1));
    EXPECT_EQ(0, pipe.ReadByteUntil(deadline, &value));
    EXPECT_EQ('R', value);
}

TEST(UfifoTestRuntimeTest, PipeReadHasBoundedTimeout)
{
    TestPipe pipe;
    ASSERT_EQ(0, TestPipe::Create(&pipe));

    char value = 0;
    TestDeadline deadline(std::chrono::milliseconds(20));
    EXPECT_EQ(-ETIMEDOUT, pipe.ReadByteUntil(deadline, &value));
}

TEST(UfifoTestRuntimeTest, ChildWaitReturnsExitStatus)
{
    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0)
        _exit(EXIT_SUCCESS);

    ChildProcess child(pid);
    int status = 0;
    TestDeadline deadline(std::chrono::seconds(1));
    ASSERT_EQ(0, child.WaitUntil(deadline, &status));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));
}

TEST(UfifoTestRuntimeTest, ChildWaitKillsTimedOutProcess)
{
    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        pause();
        _exit(EXIT_FAILURE);
    }

    ChildProcess child(pid);
    int status = 0;
    TestDeadline deadline(std::chrono::milliseconds(20));
    EXPECT_EQ(-ETIMEDOUT, child.WaitUntil(deadline, &status));
    EXPECT_FALSE(child.Valid());
}

TEST(UfifoTestRuntimeTest, WaitWordArmObservesPublishedArm)
{
    ufifo_atomic_uint32_t word = 0;
    std::thread participant([&] { __ufifo_wait_arm(&word); });
    const bool armed = WaitForWaitWordArm(&word);
    participant.join();

    EXPECT_TRUE(armed);
    EXPECT_TRUE(WaitForWaitWordArm(&word, std::chrono::milliseconds(0)));
}

TEST(UfifoTestRuntimeTest, WaitWordArmHasBoundedTimeout)
{
    ufifo_atomic_uint32_t word = 0;
    EXPECT_FALSE(WaitForWaitWordArm(&word, std::chrono::milliseconds(0)));
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(&word));
}
