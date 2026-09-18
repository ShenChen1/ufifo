#include "ufifo_test_support.hpp"

namespace {

ufifo_init_t MakeAllocOptions(bool force = true)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = force;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;
    return init;
}

ufifo_t *CreateFifo(const std::string &name)
{
    ufifo_init_t init = MakeAllocOptions();
    ufifo_t *fifo = nullptr;
    EXPECT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    return fifo;
}

} // namespace

TEST(UfifoLifetimeTest, UsesOneNamedSharedMemoryObject)
{
    const std::string name = GenerateName("single_shm");
    ufifo_t *owner = CreateFifo(name);
    ASSERT_NE(nullptr, owner);

    const std::string ctrl_name = name + UFIFO_CTRL_NAME_SUFFIX;
    errno = 0;
    const int ctrl_fd = shm_open(ctrl_name.c_str(), O_RDWR, 0);
    EXPECT_EQ(-1, ctrl_fd);
    EXPECT_EQ(ENOENT, errno);
    if (ctrl_fd >= 0)
        close(ctrl_fd);

    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoLifetimeTest, ActiveAttachPreventsDestroy)
{
    const std::string name = GenerateName("destroy_busy");
    ufifo_t *owner = CreateFifo(name);
    ASSERT_NE(nullptr, owner);

    int ready_pipe[2];
    int exit_pipe[2];
    ASSERT_EQ(0, pipe(ready_pipe));
    ASSERT_EQ(0, pipe(exit_pipe));

    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        close(ready_pipe[0]);
        close(exit_pipe[1]);
        ufifo_init_t attach = {};
        attach.opt = UFIFO_OPT_ATTACH;
        ufifo_t *client = nullptr;
        const char status = ufifo_open(name.c_str(), &attach, &client) == 0 ? '1' : '0';
        (void)write(ready_pipe[1], &status, 1);
        char signal;
        (void)read(exit_pipe[0], &signal, 1);
        _exit(status == '1' ? 0 : 1);
    }

    close(ready_pipe[1]);
    close(exit_pipe[0]);
    char status = '0';
    ASSERT_EQ(1, read(ready_pipe[0], &status, 1));
    ASSERT_EQ('1', status);

    const int ret = ufifo_destroy(owner);
    EXPECT_EQ(-EBUSY, ret);
    owner = ret == 0 ? nullptr : owner;

    ASSERT_EQ(1, write(exit_pipe[1], "x", 1));
    int child_status = 0;
    ASSERT_EQ(pid, waitpid(pid, &child_status, 0));
    EXPECT_TRUE(WIFEXITED(child_status));
    EXPECT_EQ(0, WEXITSTATUS(child_status));
    close(ready_pipe[0]);
    close(exit_pipe[1]);

    if (owner != nullptr) {
        EXPECT_EQ(0, ufifo_destroy(owner));
    }
}

TEST(UfifoLifetimeTest, ActiveGenerationPreventsForce)
{
    const std::string name = GenerateName("force_busy");
    ufifo_t *owner = CreateFifo(name);
    ASSERT_NE(nullptr, owner);

    ufifo_init_t force = MakeAllocOptions();
    ufifo_t *replacement = nullptr;
    const int ret = ufifo_open(name.c_str(), &force, &replacement);
    EXPECT_EQ(-EBUSY, ret);
    EXPECT_EQ(nullptr, replacement);

    if (replacement != nullptr) {
        EXPECT_EQ(0, ufifo_close(owner));
        EXPECT_EQ(0, ufifo_destroy(replacement));
    } else {
        EXPECT_EQ(0, ufifo_destroy(owner));
    }
}
