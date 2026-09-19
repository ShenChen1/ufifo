#include "ufifo_test_support.hpp"

TEST_F(EdgeCaseTest, AllocForceOverwrite)
{
    std::string name = GenerateName("ec_force");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    int val = 99;
    ufifo_put(fifo, &val, sizeof(val));
    ufifo_destroy(fifo);

    init.alloc.size = 128; // Force overwrite with different parameters
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    EXPECT_EQ(0, ufifo_len(fifo));
    ufifo_destroy(fifo);
}

TEST_F(EdgeCaseTest, SoleModeSlotReusePreservesUnreadData)
{
    std::string name = GenerateName("ec_sole_slot_reuse");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 3;

    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;

    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &reader));

    const char input[] = "unread";
    ASSERT_EQ(sizeof(input), ufifo_put(owner, (void *)input, sizeof(input)));

    // Release slot 0 while slot 1 remains attached and the data is unread.
    ASSERT_EQ(0, ufifo_close(owner));

    // This handle reuses slot 0. Registration must not reset SOLE's global out.
    ufifo_t *replacement = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &replacement));

    char output[sizeof(input)] = {};
    ASSERT_EQ(sizeof(output), ufifo_get(reader, output, sizeof(output)));
    EXPECT_EQ(0, memcmp(input, output, sizeof(input)));
    EXPECT_EQ(0, ufifo_len(reader));

    ufifo_close(replacement);
    ufifo_destroy(reader);
}

TEST_F(EdgeCaseTest, ProcessLockCrashRecovery)
{
    std::string name = GenerateName("ec_crash");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    pid_t pid = fork();
    if (pid == 0) {
        int val = 999;
        ufifo_put(fifo, &val, sizeof(val));
        _exit(0); // Exit abandoning the lock/handle mapping
    } else {
        ASSERT_GT(pid, 0);
        int status;
        waitpid(pid, &status, 0);

        int out = 0;
        ssize_t ret = ufifo_get(fifo, &out, sizeof(out));
        if (ret > 0) {
            EXPECT_EQ(999, out);
        }
    }
    ufifo_destroy(fifo);
}

TEST_F(EdgeCaseTest, SharedModeUserLimit)
{
    std::string name = GenerateName("ec_usrlmt");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    ufifo_t *c1 = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &c1));

    ufifo_t *c2 = nullptr;
    EXPECT_NE(0, ufifo_open(name.c_str(), &attach, &c2));

    if (c1)
        ufifo_close(c1);
    if (c2)
        ufifo_close(c2);
    if (fifo)
        ufifo_destroy(fifo);
}
