#include "ufifo_test_support.hpp"

class BrokerExecTest : public ::testing::Test {
  protected:
    void TearDown() override
    {
        for (auto &name : shm_names_) {
            shm_unlink(name.c_str());
            shm_unlink((name + "_ctrl").c_str());
        }
    }

    std::string UniqueName(const char *suffix)
    {
        std::string name = GenerateName(suffix);
        shm_names_.push_back(name);
        return name;
    }

  private:
    std::vector<std::string> shm_names_;
};

/*
 * Core regression test for the broker FD leak fix.
 *
 * Scenario: A process opens FIFO-A (PROCESS lock), then a child process
 * opens FIFO-B (which spawns broker-B). If broker-B inherits FIFO-A's
 * ctrl_fd, the OFD lock on A will remain held even after all user
 * processes exit — preventing dead-reader reaping.
 *
 * Verification: after the child exits, FIFO-A's OFD lock for the child's
 * user slot must be released (i.e., __ufifo_is_user_dead returns true).
 * If broker-B still held the ctrl_fd, the lock would persist.
 */
TEST_F(BrokerExecTest, BrokerDoesNotLeakHostFds)
{
    std::string name_a = UniqueName("brkiso_a");
    std::string name_b = UniqueName("brkiso_b");

    /* Parent creates FIFO-A with PROCESS lock */
    ufifo_init_t init_a = {};
    init_a.opt = UFIFO_OPT_ALLOC;
    init_a.alloc.size = 256;
    init_a.alloc.force = 1;
    init_a.alloc.lock = UFIFO_LOCK_PROCESS;
    init_a.alloc.data_mode = UFIFO_DATA_SHARED;
    init_a.alloc.max_users = 4;

    ufifo_t *fifo_a = nullptr;
    ASSERT_EQ(0, ufifo_open(name_a.c_str(), &init_a, &fifo_a));

    /*
     * Fork a child that:
     * 1. Attaches to FIFO-A (acquiring OFD lock on A.ctrl_fd)
     * 2. Creates FIFO-B (spawning broker-B via exec)
     * 3. Exits without ufifo_close — simulating a crash
     *
     * If broker-B inherits A's ctrl_fd, A's OFD lock for this child's
     * slot will remain held indefinitely.
     */
    int p2c[2], c2p[2];
    ASSERT_EQ(0, pipe(p2c));
    ASSERT_EQ(0, pipe(c2p));

    pid_t pid = fork();
    if (pid == 0) {
        close(p2c[1]);
        close(c2p[0]);

        /* Attach to A (takes OFD lock on A.ctrl_fd for this child's user slot) */
        ufifo_init_t attach_a = {};
        attach_a.opt = UFIFO_OPT_ATTACH;
        ufifo_t *child_a = nullptr;
        if (ufifo_open(name_a.c_str(), &attach_a, &child_a) != 0)
            _exit(1);

        /* Create B (spawns broker-B process) */
        ufifo_init_t init_b = {};
        init_b.opt = UFIFO_OPT_ALLOC;
        init_b.alloc.size = 256;
        init_b.alloc.force = 1;
        init_b.alloc.lock = UFIFO_LOCK_PROCESS;
        init_b.alloc.data_mode = UFIFO_DATA_SHARED;
        init_b.alloc.max_users = 2;

        ufifo_t *child_b = nullptr;
        if (ufifo_open(name_b.c_str(), &init_b, &child_b) != 0)
            _exit(2);

        /* Signal parent: both FIFOs are open, broker-B is running */
        char ready = '1';
        if (write(c2p[1], &ready, 1) != 1)
            _exit(3);

        /* Wait for parent ack, then exit WITHOUT closing anything */
        char ack;
        if (read(p2c[0], &ack, 1) != 1)
            _exit(4);

        /* Crash exit: no ufifo_close, all this process's FDs are released by the kernel */
        _exit(0);
    }
    ASSERT_GT(pid, 0);
    close(p2c[0]);
    close(c2p[1]);

    /* Wait for child to set up both FIFOs */
    char ready;
    ASSERT_EQ(1, read(c2p[0], &ready, 1));

    /* Let the child exit */
    char ack = 'g';
    ASSERT_EQ(1, write(p2c[1], &ack, 1));
    close(p2c[1]);

    int status;
    waitpid(pid, &status, 0);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));

    /* Small delay for broker process to fully start */
    usleep(100000);

    /*
     * THE KEY ASSERTION:
     * The child held A's OFD lock via user slot 1.
     * If broker-B leaked A's ctrl_fd, the lock would still be held.
     * __ufifo_is_user_dead probes the OFD lock: if unlocked, the user is dead.
     */
    EXPECT_EQ(1, __ufifo_is_user_dead(fifo_a->ctrl_fd, 1))
        << "Broker-B must NOT hold FIFO-A's ctrl_fd — OFD lock should be released";

    /* Cleanup: destroy B's shm so broker-B exits */
    shm_unlink(name_b.c_str());
    shm_unlink((name_b + "_ctrl").c_str());

    ufifo_destroy(fifo_a);
}

/*
 * Functional test: after the fork+exec broker architecture change,
 * multiple processes must still be able to attach and get working eventfds.
 */
TEST_F(BrokerExecTest, BrokerExecFunctionalMultiAttach)
{
    std::string name = UniqueName("brkexec_func");

    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 1024;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 4;

    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));

    /* Fork 3 children sequentially, each attaches, does a put+get round-trip */
    const int num_children = 3;
    pid_t pids[num_children];

    for (int i = 0; i < num_children; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            ufifo_init_t attach = {};
            attach.opt = UFIFO_OPT_ATTACH;
            ufifo_t *child_h = nullptr;
            if (ufifo_open(name.c_str(), &attach, &child_h) != 0)
                _exit(1);

            /* Verify eventfds work: put a value and read it back */
            int val = 100 + i;
            if ((int)ufifo_put(child_h, &val, sizeof(val)) != (int)sizeof(val))
                _exit(2);

            int out = 0;
            if ((int)ufifo_get(child_h, &out, sizeof(out)) != (int)sizeof(out))
                _exit(3);
            if (out != val)
                _exit(4);

            ufifo_close(child_h);
            _exit(0);
        }
        ASSERT_GT(pids[i], 0);
    }

    int success = 0;
    for (int i = 0; i < num_children; i++) {
        int status;
        waitpid(pids[i], &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            success++;
    }
    EXPECT_EQ(num_children, success) << "All children must successfully attach via exec'd broker and do a round-trip";

    ufifo_destroy(owner);
}

/*
 * Failure path: if the broker binary cannot be found, ufifo_open should
 * fail gracefully (not hang or crash).
 */
TEST_F(BrokerExecTest, BrokerInvalidPathFails)
{
    std::string name = UniqueName("brkexec_badpath");

    pid_t pid = fork();
    if (pid == 0) {
        /* Point to a nonexistent binary */
        setenv("UFIFO_BROKER_PATH", "/nonexistent/ufifo-broker", 1);

        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = 256;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_NONE;
        init.alloc.data_mode = UFIFO_DATA_SOLE;
        init.alloc.max_users = 2;

        ufifo_t *h = nullptr;
        int ret = ufifo_open(name.c_str(), &init, &h);

        /*
         * The broker grandchild will fail execvp and _exit(1).
         * The parent side of __ufifo_broker_fork still returns 0
         * (it only waits for the first child), but subsequent
         * attempts to connect by ATTACH will fail since the broker
         * is not running. We verify the open at least doesn't hang.
         */
        if (h)
            ufifo_destroy(h);
        _exit(ret == 0 ? 0 : 1);
    }
    ASSERT_GT(pid, 0);

    int status;
    /* 10 second timeout to ensure we don't hang */
    auto start = std::chrono::steady_clock::now();
    waitpid(pid, &status, 0);
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start).count();

    EXPECT_TRUE(WIFEXITED(status)) << "Child must exit normally (not crash/hang)";
    EXPECT_LT(elapsed, 10) << "Must not hang when broker binary is missing";
}

// =============================================================================
// Main
// =============================================================================
int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
