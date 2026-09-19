#include "ufifo_test_support.hpp"

#include <csignal>

namespace {

ufifo_init_t MakeRecoveryOptions(ufifo_lock_e lock, ufifo_data_mode_e mode)
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

} // namespace

TEST(UfifoCoreRegressionTest, ReapDoesNotRemoveReusedLiveSlot)
{
    const std::string name = GenerateName("reap_reused_slot");
    ufifo_init_t init = MakeRecoveryOptions(UFIFO_LOCK_PROCESS, UFIFO_DATA_SHARED);
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
        ufifo_init_t init = MakeRecoveryOptions(UFIFO_LOCK_NONE, UFIFO_DATA_SHARED);
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
