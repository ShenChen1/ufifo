#include "ufifo_test_support.hpp"

class FaultInjectionTest : public ::testing::Test {
  protected:
    void TearDown() override
    {
        // Clean up any leftover shared memory
        for (auto &name : shm_names_) {
            shm_unlink(name.c_str());
        }
    }

    std::string UniqueName(const char *suffix)
    {
        std::string name = std::string("/ufifo_fi_") + suffix;
        shm_names_.push_back(name);
        return name;
    }

    // Helper: create a SHARED FIFO with PROCESS lock
    int CreateFifo(const std::string &name, ufifo_t **handle, unsigned int size = 4096, unsigned int max_users = 4)
    {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_PROCESS;
        init.alloc.data_mode = UFIFO_DATA_SHARED;
        init.alloc.max_users = max_users;
        return ufifo_open(name.c_str(), &init, handle);
    }

    int AttachFifo(const std::string &name, ufifo_t **handle)
    {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ATTACH;
        return ufifo_open(name.c_str(), &init, handle);
    }

  protected:
    std::vector<std::string> shm_names_;
};

TEST_F(FaultInjectionTest, ReaderCrashRecovery)
{
    std::string name = UniqueName("rec01");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, CreateFifo(name, &fifo, 256, 2));

    int command_pipe[2], ready_pipe[2];
    ASSERT_EQ(0, pipe(command_pipe));
    ASSERT_EQ(0, pipe(ready_pipe));

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        close(command_pipe[1]);
        close(ready_pipe[0]);
        ufifo_t *child_fifo = nullptr;
        char ready = AttachFifo(name, &child_fifo) == 0 ? '1' : '0';
        if (write(ready_pipe[1], &ready, 1) != 1 || ready != '1')
            _exit(1);
        char command = 0;
        if (read(command_pipe[0], &command, 1) != 1)
            _exit(2);
        kill(getpid(), SIGKILL);
        _exit(3);
    }
    close(command_pipe[0]);
    close(ready_pipe[1]);

    char ready = 0;
    ASSERT_EQ(1, read(ready_pipe[0], &ready, 1));
    ASSERT_EQ('1', ready);
    close(ready_pipe[0]);

    char fill[256] = {};
    ASSERT_EQ(sizeof(fill), ufifo_put(fifo, fill, sizeof(fill)));
    for (size_t i = 0; i < sizeof(fill); i++)
        ASSERT_EQ(1, ufifo_skip(fifo));

    char data = 'B';
    errno = 0;
    EXPECT_EQ(-EAGAIN, ufifo_put(fifo, &data, 1));
    EXPECT_EQ(EAGAIN, errno);

    char command = 'k';
    ASSERT_EQ(1, write(command_pipe[1], &command, 1));
    close(command_pipe[1]);
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFSIGNALED(status));
    ASSERT_EQ(SIGKILL, WTERMSIG(status));

    EXPECT_EQ(1, ufifo_put_timeout(fifo, &data, 1, 1000));
    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST_F(FaultInjectionTest, AllReadersCrash)
{
    std::string name = UniqueName("rec05");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, CreateFifo(name, &fifo, 256, 4));

    int p2c[3][2], c2p[3][2];
    pid_t pids[3];
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(0, pipe(p2c[i]));
        ASSERT_EQ(0, pipe(c2p[i]));
        pids[i] = fork();
        if (pids[i] == 0) {
            for (int j = 0; j < i; j++) {
                close(p2c[j][1]);
                close(c2p[j][0]);
            }
            close(p2c[i][1]);
            close(c2p[i][0]);
            ufifo_t *child_fifo = nullptr;
            if (AttachFifo(name, &child_fifo) == 0) {
                char ready = '1';
                write(c2p[i][1], &ready, 1);
                char wait_cmd;
                read(p2c[i][0], &wait_cmd, 1);
                kill(getpid(), SIGKILL);
            }
            _exit(1);
        }
        ASSERT_GT(pids[i], 0);
        close(p2c[i][0]);
        close(c2p[i][1]);
    }

    for (int i = 0; i < 3; i++) {
        char ready = 0;
        ASSERT_EQ(1, read(c2p[i][0], &ready, 1));
        ASSERT_EQ('1', ready);
        close(c2p[i][0]);
    }

    char fill[256] = {};
    ASSERT_EQ(sizeof(fill), ufifo_put(fifo, fill, sizeof(fill)));
    for (size_t i = 0; i < sizeof(fill); i++)
        ASSERT_EQ(1, ufifo_skip(fifo));

    char data = 'B';
    errno = 0;
    EXPECT_EQ(-EAGAIN, ufifo_put(fifo, &data, 1));
    EXPECT_EQ(EAGAIN, errno);

    for (int i = 0; i < 3; i++) {
        char command = 'k';
        ASSERT_EQ(1, write(p2c[i][1], &command, 1));
        close(p2c[i][1]);
        int status = 0;
        ASSERT_EQ(pids[i], waitpid(pids[i], &status, 0));
        ASSERT_TRUE(WIFSIGNALED(status));
        ASSERT_EQ(SIGKILL, WTERMSIG(status));
    }

    EXPECT_EQ(1, ufifo_put_timeout(fifo, &data, 1, 1000));
    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST_F(FaultInjectionTest, ConcurrentAttachRace)
{
    std::string name = UniqueName("brk03");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, CreateFifo(name, &fifo, 256, 16));

    const int num_procs = 8;
    pid_t pids[num_procs];

    for (int i = 0; i < num_procs; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            ufifo_t *child_fifo = nullptr;
            if (AttachFifo(name, &child_fifo) == 0) {
                // Exit without ufifo_close to simulate concurrent attach/detach race conditions
                _exit(0);
            }
            _exit(1);
        }
        ASSERT_GT(pids[i], 0);
    }

    int success_count = 0;
    for (int i = 0; i < num_procs; i++) {
        int status;
        waitpid(pids[i], &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            success_count++;
        }
    }

    EXPECT_EQ(num_procs, success_count);

    char data[10] = "test";
    EXPECT_EQ(10u, ufifo_put(fifo, data, 10));

    ufifo_destroy(fifo);
}

TEST_F(FaultInjectionTest, CtrlMutexOwnerDeath)
{
    std::string name = UniqueName("rec03");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, CreateFifo(name, &fifo, 4096, 4));

    int p2c[2], c2p[2];
    ASSERT_EQ(0, pipe(p2c));
    ASSERT_EQ(0, pipe(c2p));

    pid_t pid = fork();
    if (pid == 0) {
        close(p2c[1]);
        close(c2p[0]);
        ufifo_t *child_fifo = nullptr;
        if (AttachFifo(name, &child_fifo) == 0) {
            pthread_mutex_lock(&child_fifo->ctrl->ctrl_mutex);
            child_fifo->ctrl->num_users = 99; // Corrupt state
            char ready = '1';
            write(c2p[1], &ready, 1);
            char wait_cmd;
            read(p2c[0], &wait_cmd, 1); // wait for parent
            kill(getpid(), SIGKILL);
        }
        _exit(1);
    }
    ASSERT_GT(pid, 0);
    close(p2c[0]);
    close(c2p[1]);

    char ready;
    EXPECT_EQ(1, read(c2p[0], &ready, 1));
    close(p2c[1]); // unblocks child's read, triggering SIGKILL

    int status;
    waitpid(pid, &status, 0);

    ufifo_t *new_reader = nullptr;
    int ret = AttachFifo(name, &new_reader);
    ASSERT_EQ(0, ret);

    unsigned int expected_users = 2; // parent + new_reader
    EXPECT_EQ(expected_users, fifo->ctrl->num_users);

    ufifo_close(new_reader);
    ufifo_destroy(fifo);
}

TEST_F(FaultInjectionTest, ExistingHandleSurvivesCtrlMutexRecovery)
{
    std::string name = UniqueName("ctrl_self");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, CreateFifo(name, &fifo, 4096, 2));

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        ufifo_t *child_fifo = nullptr;
        if (AttachFifo(name, &child_fifo) != 0)
            _exit(1);
        if (pthread_mutex_lock(&child_fifo->ctrl->ctrl_mutex) != 0)
            _exit(2);
        child_fifo->ctrl->num_users = 99;
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));

    ASSERT_EQ(0, __ufifo_ctrl_lock(fifo));
    EXPECT_TRUE(READ_ONCE(&fifo->ctrl->users[fifo->user_id].active));
    EXPECT_EQ(1U, fifo->ctrl->num_users);
    EXPECT_EQ(0, __ufifo_ctrl_unlock(fifo));
    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST_F(FaultInjectionTest, DataMutexOwnerDeathResetsAndReportsOnce)
{
    std::string name = UniqueName("data_owner_death");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, CreateFifo(name, &fifo, 256, 2));

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        ufifo_t *child_fifo = nullptr;
        if (AttachFifo(name, &child_fifo) != 0)
            _exit(1);
        if (pthread_mutex_lock(&child_fifo->ctrl->data_mutex) != 0)
            _exit(2);
        static_cast<char *>(child_fifo->shm_mem)[0] = 'Q';
        smp_store_release(&child_fifo->ctrl->in, 1);
        _exit(0);
    }

    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));

    char output = 0;
    errno = 0;
    EXPECT_EQ(-EOWNERDEAD, ufifo_get(fifo, &output, sizeof(output)));
    EXPECT_EQ(EOWNERDEAD, errno);
    EXPECT_EQ(0, ufifo_len(fifo));

    char input = 'R';
    EXPECT_EQ(1, ufifo_put(fifo, &input, sizeof(input)));
    EXPECT_EQ(1, ufifo_get(fifo, &output, sizeof(output)));
    EXPECT_EQ(input, output);
    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST_F(FaultInjectionTest, LockNoneWaiterRace)
{
    std::string name = UniqueName("not04");
    ufifo_t *fifo = nullptr;
    {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = 4096;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_NONE;
        init.alloc.data_mode = UFIFO_DATA_SOLE;
        init.alloc.max_users = 4;
        ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    }

    std::atomic<int> total_written{ 0 };
    std::atomic<int> total_read{ 0 };
    std::atomic<int> operation_error{ 0 };
    std::atomic<bool> running{ true };
    const int target = 10000;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    std::thread writer([&]() {
        char data = 'X';
        while (total_written < target && operation_error.load() == 0) {
            ssize_t ret = ufifo_put(fifo, &data, 1);
            if (ret == 1) {
                total_written++;
            } else if (ret != -EAGAIN) {
                operation_error.store(ret < 0 ? static_cast<int>(ret) : -EIO);
                break;
            } else if (std::chrono::steady_clock::now() >= deadline) {
                operation_error.store(-ETIMEDOUT);
                break;
            } else {
                std::this_thread::yield();
            }
        }
        running = false;
    });

    std::thread reader([&]() {
        char buf;
        while (operation_error.load() == 0 && (running || total_read < total_written)) {
            ssize_t ret = ufifo_get_timeout(fifo, &buf, 1, 100);
            if (ret == 1) {
                total_read++;
            } else if (ret != -ETIMEDOUT && ret != -EAGAIN) {
                operation_error.store(ret < 0 ? static_cast<int>(ret) : -EIO);
                break;
            } else if (std::chrono::steady_clock::now() >= deadline) {
                operation_error.store(-ETIMEDOUT);
                break;
            }
        }
    });

    writer.join();
    reader.join();

    EXPECT_EQ(0, operation_error.load());
    EXPECT_EQ(target, total_written.load());
    EXPECT_EQ(total_written.load(), total_read.load());
    EXPECT_EQ(0, ufifo_destroy(fifo));
}
