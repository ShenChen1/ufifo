#include "ufifo_test_support.hpp"

class UfifoReapTest : public ::testing::Test {
  protected:
    std::string name;

    void SetUp() override
    {
        name = GenerateName("reap_test");
    }

    void TearDown() override
    {
        shm_unlink(name.c_str());
    }
};

TEST_F(UfifoReapTest, ReapDeadUserOnRegister)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 1024;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.force = 1;

    ufifo_t *fifo1 = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo1));

    pid_t pid = fork();
    if (pid == 0) {
        ufifo_init_t attach_init = {};
        attach_init.opt = UFIFO_OPT_ATTACH;
        ufifo_t *fifo_child = nullptr;
        _exit(ufifo_open(name.c_str(), &attach_init, &fifo_child) == 0 ? 0 : 1);
    }

    int status;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    ufifo_t *fifo2 = nullptr;
    ufifo_init_t attach_init = {};
    attach_init.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach_init, &fifo2));

    EXPECT_EQ(0, ufifo_close(fifo2));
    EXPECT_EQ(0, ufifo_destroy(fifo1));
}

TEST_F(UfifoReapTest, ReapDeadUserOnPut)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.force = 1;

    ufifo_t *producer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &producer));

    pid_t pid = fork();
    if (pid == 0) {
        ufifo_init_t attach_init = {};
        attach_init.opt = UFIFO_OPT_ATTACH;
        ufifo_t *reader = nullptr;
        if (ufifo_open(name.c_str(), &attach_init, &reader) == 0) {
            char value;
            if (ufifo_get_block(reader, &value, 1) == 1)
                _exit(0);
        }
        _exit(1);
    }

    usleep(100000);
    char data = 'A';
    ASSERT_EQ(1, ufifo_put(producer, &data, 1));
    ASSERT_EQ(1, ufifo_skip(producer));

    int status;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    char buffer[64];
    memset(buffer, 'B', sizeof(buffer));
    ASSERT_EQ(63, ufifo_put(producer, buffer, 63));
    for (int i = 0; i < 63; i++)
        ASSERT_EQ(1, ufifo_skip(producer));

    EXPECT_EQ(2, ufifo_put(producer, buffer, 2));
    EXPECT_EQ(0, ufifo_destroy(producer));
}
