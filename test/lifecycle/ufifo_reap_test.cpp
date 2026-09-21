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

    int ready_pipe[2];
    ASSERT_EQ(0, pipe(ready_pipe));
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        close(ready_pipe[0]);
        ufifo_init_t attach_init = {};
        attach_init.opt = UFIFO_OPT_ATTACH;
        ufifo_t *reader = nullptr;
        char ready = ufifo_open(name.c_str(), &attach_init, &reader) == 0 ? '1' : '0';
        if (write(ready_pipe[1], &ready, 1) != 1 || ready != '1')
            _exit(1);
        char value = 0;
        _exit(ufifo_get_timeout(reader, &value, 1, 1000) == 1 && value == 'A' ? 0 : 1);
    }

    close(ready_pipe[1]);
    char ready = 0;
    ASSERT_EQ(1, read(ready_pipe[0], &ready, 1));
    ASSERT_EQ('1', ready);
    close(ready_pipe[0]);

    char data = 'A';
    ASSERT_EQ(1, ufifo_put(producer, &data, 1));
    ASSERT_EQ(1, ufifo_skip(producer));

    int status;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    char buffer[64] = {};
    memset(buffer, 'B', sizeof(buffer));
    ASSERT_EQ(sizeof(buffer), ufifo_put(producer, buffer, sizeof(buffer)));
    for (size_t i = 0; i < sizeof(buffer); i++)
        ASSERT_EQ(1, ufifo_skip(producer));

    EXPECT_EQ(1, ufifo_put_timeout(producer, buffer, 1, 1000));
    EXPECT_EQ(0, ufifo_destroy(producer));
}
