#include <array>
#include <functional>
#include <gtest/gtest.h>
#include <new>
#include <tuple>
#include <vector>

extern "C" {
#include "ufifo_internal.h"
uint32_t __real___ufifo_wait_arm(ufifo_atomic_uint32_t *word);
}

namespace {

constexpr size_t kCapacity = 64;
constexpr size_t kRequestedSpace = 4;
constexpr size_t kMaximumWaitCalls = 16;
enum class Direction { Rx, SoleTx, SharedTx };
enum class Event { Arm, Unlock, Wait, Relock };
using Configuration = std::tuple<Direction, ufifo_wait_type_e>;

struct WaitScript {
    ufifo_t *handle = nullptr;
    ufifo_atomic_uint32_t *word = nullptr;
    const timespec *deadline = nullptr;
    timespec deadline_value = {};
    bool capture_initial_deadline = false;
    bool lock_held = true;
    int unlock_result = 0;
    int relock_result = 0;
    uint32_t armed_epoch = 0;
    size_t wait_calls = 0;
    std::vector<Event> events;
    std::vector<uint32_t> expected_epochs;
    std::function<void()> after_arm;
    std::function<void()> after_unlock;
    std::function<int()> wait_result;

    void CheckDeadline(const timespec *actual) const
    {
        EXPECT_EQ(deadline, actual);
        if (actual != nullptr) {
            EXPECT_EQ(deadline_value.tv_sec, actual->tv_sec);
            EXPECT_EQ(deadline_value.tv_nsec, actual->tv_nsec);
        }
    }
};

// Link-time doubles belong to this single-threaded executable, never to the library.
WaitScript *current_script = nullptr;

class UfifoWaitProtocolTest : public ::testing::TestWithParam<Configuration> {
  protected:
    void SetUp() override
    {
        ctrl_ = new (control_storage_.data()) ufifo_ctrl_t{};
        new (&ctrl_->users[0]) ufifo_sub_ctrl_t{};
        ctrl_->max_users = 1;
        ctrl_->users[0].active = true;
        handle_.ctrl = ctrl_;
        ASSERT_EQ(0, __ufifo_process_identity_init());
        handle_.magic = UFIFO_MAGIC;
        handle_.owner_pid = __ufifo_process_pid();
        handle_.shm_mem = data_.data();
        handle_.user_id = 0;
        handle_.is_shared = std::get<0>(GetParam()) == Direction::SharedTx;
        handle_.kfifo.in = &ctrl_->in;
        handle_.kfifo.out = &ctrl_->users[0].out;
        handle_.kfifo.mask = kCapacity - 1;
        if (!IsRx())
            ufifo_atomic_store_release(&ctrl_->in, kCapacity);
        script_.handle = &handle_;
        script_.word = IsRx() ? __ufifo_rx_wait_word(&handle_) : __ufifo_tx_wait_word(&handle_);
        script_.deadline = std::get<1>(GetParam()) == UFIFO_WAIT_TIMED ? &deadline_ : nullptr;
        script_.deadline_value = deadline_;
        ufifo_atomic_store_relaxed(script_.word, 40U);
        current_script = &script_;
        errno = 0;
    }

    void TearDown() override
    {
        current_script = nullptr;
        ctrl_->users[0].~ufifo_sub_ctrl_t();
        ctrl_->~ufifo_ctrl_t();
    }

    bool IsRx() const
    {
        return std::get<0>(GetParam()) == Direction::Rx;
    }

    void PublishReady()
    {
        if (IsRx()) {
            ufifo_atomic_store_release(&ctrl_->in, 1);
        } else {
            ufifo_atomic_store_release(&ctrl_->users[0].out, kRequestedSpace);
            if (handle_.is_shared)
                ufifo_atomic_store_release(&ctrl_->cached_min_out, kRequestedSpace);
        }
    }

    int Run(ufifo_wait_type_e wait_type)
    {
        if (IsRx())
            return __ufifo_wait_for_data(&handle_, wait_type, script_.deadline, &result_);
        return __ufifo_wait_for_space(&handle_, kRequestedSpace, wait_type, script_.deadline, &result_);
    }

    int Run()
    {
        return Run(std::get<1>(GetParam()));
    }

    ssize_t RunOperation()
    {
        script_.lock_held = false;
        script_.capture_initial_deadline = true;
        char buffer[kRequestedSpace] = {};
        if (std::get<1>(GetParam()) == UFIFO_WAIT_TIMED) {
            return IsRx() ? ufifo_get_timeout(&handle_, buffer, sizeof(buffer), 2000)
                          : ufifo_put_timeout(&handle_, buffer, sizeof(buffer), 2000);
        }
        return IsRx() ? ufifo_get_block(&handle_, buffer, sizeof(buffer))
                      : ufifo_put_block(&handle_, buffer, sizeof(buffer));
    }

    void ExpectReady()
    {
        EXPECT_EQ(IsRx() ? 1U : kRequestedSpace, result_.length);
        EXPECT_TRUE(result_.data_lock_held);
        EXPECT_TRUE(script_.lock_held);
    }

    void ExpectError(int error, bool lock_held)
    {
        EXPECT_EQ(error, errno);
        EXPECT_EQ(0U, result_.length);
        EXPECT_EQ(lock_held, result_.data_lock_held);
    }

    void ExpectOneWait()
    {
        EXPECT_EQ((std::vector<Event>{ Event::Arm, Event::Unlock, Event::Wait, Event::Relock }), script_.events);
        EXPECT_EQ((std::vector<uint32_t>{ 41U }), script_.expected_epochs);
    }

    alignas(ufifo_ctrl_t) std::array<unsigned char, sizeof(ufifo_ctrl_t) + sizeof(ufifo_sub_ctrl_t)> control_storage_{};
    ufifo_ctrl_t *ctrl_ = nullptr;
    ufifo_t handle_ = {};
    timespec deadline_ = { 123, 456 };
    ufifo_wait_result_t result_ = { 0, true };
    std::array<char, kCapacity> data_{};
    WaitScript script_;
};

TEST_P(UfifoWaitProtocolTest, ReadyPredicateNeverArmsOrUnlocks)
{
    PublishReady();
    EXPECT_EQ(0, Run());
    ExpectReady();
    EXPECT_TRUE(script_.events.empty());
}

TEST_P(UfifoWaitProtocolTest, NonblockingFailureNeverArmsOrUnlocks)
{
    EXPECT_EQ(-EAGAIN, Run(UFIFO_WAIT_NONE));
    ExpectError(EAGAIN, true);
    EXPECT_TRUE(script_.events.empty());
}

TEST_P(UfifoWaitProtocolTest, PublicationAfterArmSkipsSleep)
{
    script_.after_arm = [&] { PublishReady(); };
    EXPECT_EQ(0, Run());
    ExpectReady();
    EXPECT_EQ((std::vector<Event>{ Event::Arm }), script_.events);
}

TEST_P(UfifoWaitProtocolTest, PublicationAfterUnlockKeepsOriginalExpectedEpoch)
{
    script_.after_unlock = [&] {
        PublishReady();
        __ufifo_wait_notify(script_.word);
    };
    script_.wait_result = [&] {
        EXPECT_NE(script_.armed_epoch, ufifo_atomic_load_acquire(script_.word));
        return 0; // The real primitive normalizes an epoch mismatch (EAGAIN) to retry.
    };
    EXPECT_EQ(0, Run());
    ExpectReady();
    ExpectOneWait();
}

TEST_P(UfifoWaitProtocolTest, SpuriousReturnRechecksPredicateAndReusesDeadline)
{
    script_.wait_result = [&] {
        if (script_.wait_calls == 2)
            PublishReady();
        return 0;
    };
    EXPECT_EQ(0, Run());
    ExpectReady();
    EXPECT_EQ((std::vector<Event>{ Event::Arm,
                                   Event::Unlock,
                                   Event::Wait,
                                   Event::Relock,
                                   Event::Arm,
                                   Event::Unlock,
                                   Event::Wait,
                                   Event::Relock }),
              script_.events);
    EXPECT_EQ((std::vector<uint32_t>{ 41U, 41U }), script_.expected_epochs);
}

TEST_P(UfifoWaitProtocolTest, NotificationWithoutPredicateRearmsNewEpoch)
{
    script_.wait_result = [&] {
        if (script_.wait_calls == 1) {
            __ufifo_wait_notify(script_.word);
            return 0;
        }
        return -ETIMEDOUT;
    };
    EXPECT_EQ(-ETIMEDOUT, Run());
    ExpectError(ETIMEDOUT, true);
    EXPECT_EQ((std::vector<uint32_t>{ 41U, 43U }), script_.expected_epochs);
    EXPECT_EQ(43U, ufifo_atomic_load_acquire(script_.word));
}

TEST_P(UfifoWaitProtocolTest, InterruptedWaitReacquiresLockBeforeReturning)
{
    script_.wait_result = [] { return -EINTR; };
    EXPECT_EQ(-EINTR, Run());
    ExpectError(EINTR, true);
    ExpectOneWait();
}

TEST_P(UfifoWaitProtocolTest, TimedOutWaitReacquiresLockBeforeReturning)
{
    EXPECT_EQ(-ETIMEDOUT, Run());
    ExpectError(ETIMEDOUT, true);
    ExpectOneWait();
    EXPECT_EQ(41U, ufifo_atomic_load_acquire(script_.word));
}

TEST_P(UfifoWaitProtocolTest, RelockTimeoutOverridesWaitInterruption)
{
    script_.wait_result = [] { return -EINTR; };
    script_.relock_result = -ETIMEDOUT;
    EXPECT_EQ(-ETIMEDOUT, Run());
    ExpectError(ETIMEDOUT, false);
    EXPECT_FALSE(script_.lock_held);
    ExpectOneWait();
}

TEST_P(UfifoWaitProtocolTest, RelockOwnerDeathReturnsWithoutLockOwnership)
{
    script_.wait_result = [&] {
        PublishReady();
        return 0;
    };
    script_.relock_result = -EOWNERDEAD;
    EXPECT_EQ(-EOWNERDEAD, Run());
    ExpectError(EOWNERDEAD, false);
    EXPECT_FALSE(script_.lock_held);
    ExpectOneWait();
}

TEST_P(UfifoWaitProtocolTest, UnlockFailureDoesNotWaitOrRelock)
{
    script_.unlock_result = -EPERM;
    EXPECT_EQ(-EPERM, Run());
    ExpectError(EPERM, false);
    EXPECT_EQ((std::vector<Event>{ Event::Arm, Event::Unlock }), script_.events);
}

TEST_P(UfifoWaitProtocolTest, OperationDoesNotUnlockAfterRelockTimeout)
{
    script_.wait_result = [&] {
        script_.relock_result = -ETIMEDOUT;
        return -EINTR;
    };
    EXPECT_EQ(-ETIMEDOUT, RunOperation());
    EXPECT_EQ(ETIMEDOUT, errno);
    EXPECT_FALSE(script_.lock_held);
    EXPECT_EQ((std::vector<Event>{ Event::Relock, Event::Arm, Event::Unlock, Event::Wait, Event::Relock }),
              script_.events);
}

TEST_P(UfifoWaitProtocolTest, OperationDoesNotUnlockAfterRelockOwnerDeath)
{
    script_.wait_result = [&] {
        PublishReady();
        script_.relock_result = -EOWNERDEAD;
        return 0;
    };
    EXPECT_EQ(-EOWNERDEAD, RunOperation());
    EXPECT_EQ(EOWNERDEAD, errno);
    EXPECT_FALSE(script_.lock_held);
    EXPECT_EQ((std::vector<Event>{ Event::Relock, Event::Arm, Event::Unlock, Event::Wait, Event::Relock }),
              script_.events);
}

TEST_P(UfifoWaitProtocolTest, OperationUnlocksReacquiredLockAfterInterruption)
{
    script_.wait_result = [] { return -EINTR; };
    EXPECT_EQ(-EINTR, RunOperation());
    EXPECT_EQ(EINTR, errno);
    EXPECT_FALSE(script_.lock_held);
    EXPECT_EQ(
        (std::vector<Event>{ Event::Relock, Event::Arm, Event::Unlock, Event::Wait, Event::Relock, Event::Unlock }),
        script_.events);
}

INSTANTIATE_TEST_SUITE_P(DirectionsAndWaitTypes,
                         UfifoWaitProtocolTest,
                         ::testing::Combine(::testing::Values(Direction::Rx, Direction::SoleTx, Direction::SharedTx),
                                            ::testing::Values(UFIFO_WAIT_BLOCK, UFIFO_WAIT_TIMED)),
                         [](const ::testing::TestParamInfo<Configuration> &info) {
                             const Direction direction = std::get<0>(info.param);
                             const std::string name = direction == Direction::Rx       ? "Rx"
                                                      : direction == Direction::SoleTx ? "SoleTx"
                                                                                       : "SharedTx";
                             return name + (std::get<1>(info.param) == UFIFO_WAIT_TIMED ? "Timed" : "Block");
                         });

} // namespace

extern "C" uint32_t __wrap___ufifo_wait_arm(ufifo_atomic_uint32_t *word)
{
    auto &script = *current_script;
    EXPECT_TRUE(script.lock_held);
    EXPECT_EQ(script.word, word);
    script.events.push_back(Event::Arm);
    script.armed_epoch = __real___ufifo_wait_arm(word);
    if (script.after_arm)
        script.after_arm();
    return script.armed_epoch;
}

extern "C" int __wrap___ufifo_data_unlock(ufifo_t *handle)
{
    auto &script = *current_script;
    EXPECT_EQ(script.handle, handle);
    EXPECT_TRUE(script.lock_held);
    script.events.push_back(Event::Unlock);
    if (script.unlock_result < 0)
        return script.unlock_result;
    script.lock_held = false;
    if (script.after_unlock)
        script.after_unlock();
    return 0;
}

extern "C" int __wrap___ufifo_futex_wait(ufifo_atomic_uint32_t *word, uint32_t expected, const timespec *deadline)
{
    auto &script = *current_script;
    EXPECT_EQ(script.word, word);
    EXPECT_FALSE(script.lock_held);
    EXPECT_EQ(script.armed_epoch, expected);
    script.CheckDeadline(deadline);
    script.events.push_back(Event::Wait);
    script.expected_epochs.push_back(expected);
    if (++script.wait_calls > kMaximumWaitCalls) {
        ADD_FAILURE() << "Wait policy exceeded the bounded script";
        return -ETIMEDOUT;
    }
    return script.wait_result ? script.wait_result() : -ETIMEDOUT;
}

extern "C" int __wrap___ufifo_data_lock_until(ufifo_t *handle, const timespec *deadline)
{
    auto &script = *current_script;
    EXPECT_EQ(script.handle, handle);
    EXPECT_FALSE(script.lock_held);
    if (script.capture_initial_deadline) {
        script.deadline = deadline;
        script.deadline_value = deadline == nullptr ? timespec{} : *deadline;
        script.capture_initial_deadline = false;
    }
    script.CheckDeadline(deadline);
    script.events.push_back(Event::Relock);
    script.lock_held = script.relock_result == 0;
    return script.relock_result;
}
