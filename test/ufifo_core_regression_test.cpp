#include "ufifo_test_support.hpp"

#include <csignal>

namespace {

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

bool WaitUntilArmed(uint32_t *wait_word, std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while ((smp_load_acquire(wait_word) & 1U) == 0) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::yield();
    }
    return true;
}

} // namespace

TEST(UfifoCoreRegressionTest, ReapDoesNotRemoveReusedLiveSlot)
{
    const std::string name = GenerateName("reap_reused_slot");
    ufifo_init_t init = MakeCoreOptions(UFIFO_LOCK_PROCESS, UFIFO_DATA_SHARED);
    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));

    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        ufifo_init_t attach = {};
        attach.opt = UFIFO_OPT_ATTACH;
        ufifo_t *reader = nullptr;
        _exit(ufifo_open(name.c_str(), &attach, &reader) == 0 ? 0 : 1);
    }

    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *replacement = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &replacement));
    ASSERT_EQ(0, __ufifo_ctrl_lock(owner));
    __ufifo_reap_dead_user(owner, replacement->user_id);
    ASSERT_EQ(0, __ufifo_ctrl_unlock(owner));

    EXPECT_TRUE(smp_load_acquire(&owner->ctrl->users[replacement->user_id].active));
    EXPECT_EQ(2U, owner->ctrl->num_users);
    EXPECT_EQ(0, ufifo_close(replacement));
    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoCoreRegressionTest, ControlMutexRecoversWithLockNone)
{
    const std::string name = GenerateName("lock_none_ctrl_owner_death");
    const pid_t scenario = fork();
    ASSERT_GE(scenario, 0);
    if (scenario == 0) {
        ufifo_init_t init = MakeCoreOptions(UFIFO_LOCK_NONE, UFIFO_DATA_SHARED);
        ufifo_t *owner = nullptr;
        if (ufifo_open(name.c_str(), &init, &owner) != 0)
            _exit(1);

        const pid_t holder = fork();
        if (holder == 0) {
            ufifo_init_t attach = {};
            attach.opt = UFIFO_OPT_ATTACH;
            ufifo_t *reader = nullptr;
            if (ufifo_open(name.c_str(), &attach, &reader) != 0)
                _exit(2);
            if (pthread_mutex_lock(&reader->ctrl->ctrl_mutex) != 0)
                _exit(3);
            _exit(0);
        }

        int holder_status = 0;
        if (holder < 0 || waitpid(holder, &holder_status, 0) != holder || holder_status != 0)
            _exit(4);
        alarm(1);
        if (__ufifo_ctrl_lock(owner) != 0)
            _exit(5);
        alarm(0);
        if (__ufifo_ctrl_unlock(owner) != 0 || ufifo_destroy(owner) != 0)
            _exit(6);
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(scenario, waitpid(scenario, &status, 0));
    EXPECT_TRUE(WIFEXITED(status));
    EXPECT_EQ(0, WEXITSTATUS(status));
    shm_unlink(name.c_str());
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
    while (!started.load())
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    ASSERT_EQ(0, pthread_mutex_unlock(&fifo->ctrl->data_mutex));
    waiter.join();

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
    uint32_t *wait_word = &__ufifo_rx_ctrl(fifo)->rx_wait_word;
    const bool armed = WaitUntilArmed(wait_word, std::chrono::seconds(1));
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
