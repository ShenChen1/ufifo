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

    ASSERT_GT(pid, 0);
    ChildProcess child(pid);
    int status = 0;
    TestDeadline child_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, child.WaitUntil(child_deadline, &status));
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

    TestPipe ready_pipe;
    ASSERT_EQ(0, TestPipe::Create(&ready_pipe));
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        ready_pipe.CloseRead();
        ufifo_init_t attach_init = {};
        attach_init.opt = UFIFO_OPT_ATTACH;
        ufifo_t *reader = nullptr;
        const char ready = ufifo_open(name.c_str(), &attach_init, &reader) == 0 ? '1' : '0';
        if (ready_pipe.WriteByte(ready) != 0 || ready != '1')
            _exit(1);
        char value = 0;
        _exit(ufifo_get_timeout(reader, &value, 1, 1000) == 1 && value == 'A' ? 0 : 1);
    }

    ChildProcess child(pid);
    ready_pipe.CloseWrite();
    char ready = 0;
    TestDeadline ready_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, ready_pipe.ReadByteUntil(ready_deadline, &ready));
    ASSERT_EQ('1', ready);

    char data = 'A';
    ASSERT_EQ(1, ufifo_put(producer, &data, 1));
    ASSERT_EQ(1, ufifo_skip(producer));

    int status = 0;
    TestDeadline child_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, child.WaitUntil(child_deadline, &status));
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    char buffer[64] = {};
    memset(buffer, 'B', sizeof(buffer));
    ASSERT_EQ(sizeof(buffer), ufifo_put(producer, buffer, sizeof(buffer)));
    for (size_t i = 0; i < sizeof(buffer); i++)
        ASSERT_EQ(1, ufifo_skip(producer));

    EXPECT_EQ(1, ufifo_put_timeout(producer, buffer, 1, 1000));
    EXPECT_EQ(0, ufifo_destroy(producer));
}
