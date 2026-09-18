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

void RunAttachForceRace()
{
    const std::string name = GenerateName("generation_race");
    ufifo_t *initial = CreateFifo(name);
    ASSERT_NE(nullptr, initial);
    ASSERT_EQ(0, ufifo_close(initial));

    std::atomic<bool> start{ false };
    ufifo_t *attached = nullptr;
    ufifo_t *replacement = nullptr;
    int attach_ret = -1;
    int force_ret = -1;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_init_t force = MakeAllocOptions();
    force.alloc.size = 128;

    std::thread attach_thread([&]() {
        while (!start.load()) {
        }
        attach_ret = ufifo_open(name.c_str(), &attach, &attached);
    });
    std::thread force_thread([&]() {
        while (!start.load()) {
        }
        force_ret = ufifo_open(name.c_str(), &force, &replacement);
    });
    start.store(true);
    attach_thread.join();
    force_thread.join();

    ASSERT_TRUE(attach_ret == 0 || attach_ret == -EAGAIN || attach_ret == -ENOENT);
    ASSERT_TRUE(force_ret == 0 || force_ret == -EBUSY);
    if (force_ret == 0) {
        EXPECT_EQ(128U, ufifo_size(replacement));
        if (attach_ret == 0) {
            EXPECT_EQ(128U, ufifo_size(attached));
            EXPECT_EQ(0, ufifo_close(attached));
        } else {
            EXPECT_EQ(nullptr, attached);
        }
        EXPECT_EQ(0, ufifo_destroy(replacement));
    } else {
        ASSERT_EQ(0, attach_ret);
        EXPECT_EQ(nullptr, replacement);
        EXPECT_EQ(64U, ufifo_size(attached));
        EXPECT_EQ(0, ufifo_destroy(attached));
    }
}

} // namespace

TEST(UfifoLifetimeTest, UsesOneNamedSharedMemoryObject)
{
    const std::string name = GenerateName("single_shm");
    ufifo_t *owner = CreateFifo(name);
    ASSERT_NE(nullptr, owner);

    const std::string ctrl_name = name + "_ctrl";
    errno = 0;
    const int ctrl_fd = shm_open(ctrl_name.c_str(), O_RDWR, 0);
    EXPECT_EQ(-1, ctrl_fd);
    EXPECT_EQ(ENOENT, errno);
    if (ctrl_fd >= 0)
        close(ctrl_fd);

    struct stat stat_buffer = {};
    ASSERT_EQ(0, fstat(owner->shm_fd, &stat_buffer));
    EXPECT_EQ(owner->mapping_size, static_cast<size_t>(stat_buffer.st_size));
    EXPECT_EQ(owner->mapping_size, owner->ctrl->mapping_size);
    EXPECT_EQ(owner->shm_size, owner->ctrl->data_size);
    EXPECT_EQ(static_cast<void *>(reinterpret_cast<char *>(owner->ctrl) + owner->ctrl->data_offset), owner->shm_mem);

    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoLifetimeTest, AttachToUninitializedObjectReturnsAgain)
{
    const std::string name = GenerateName("attach_uninitialized");
    const int fd = shm_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    ASSERT_GE(fd, 0);

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *fifo = nullptr;
    EXPECT_EQ(-EAGAIN, ufifo_open(name.c_str(), &attach, &fifo));
    EXPECT_EQ(nullptr, fifo);

    close(fd);
    EXPECT_EQ(0, shm_unlink(name.c_str()));
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
    if (owner != nullptr) {
        int value = 41;
        int output = 0;
        EXPECT_EQ(sizeof(value), ufifo_put(owner, &value, sizeof(value)));
        EXPECT_EQ(sizeof(output), ufifo_get(owner, &output, sizeof(output)));
        EXPECT_EQ(value, output);
    }

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
        int value = 73;
        int output = 0;
        EXPECT_EQ(sizeof(value), ufifo_put(owner, &value, sizeof(value)));
        EXPECT_EQ(sizeof(output), ufifo_get(owner, &output, sizeof(output)));
        EXPECT_EQ(value, output);
        EXPECT_EQ(0, ufifo_destroy(owner));
    }
}

TEST(UfifoLifetimeTest, ForceRejectsNonCurrentLayout)
{
    const std::string name = GenerateName("force_layout");
    const size_t mapping_size = 4096;
    int fd = shm_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(0, ftruncate(fd, mapping_size));
    void *mapping = mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    ASSERT_NE(MAP_FAILED, mapping);
    static_cast<ufifo_ctrl_t *>(mapping)->layout_abi = UFIFO_LAYOUT_ABI - 1;
    ASSERT_EQ(0, munmap(mapping, mapping_size));
    close(fd);

    ufifo_init_t force = MakeAllocOptions();
    ufifo_t *replacement = nullptr;
    EXPECT_EQ(-EPROTO, ufifo_open(name.c_str(), &force, &replacement));
    EXPECT_EQ(nullptr, replacement);
    EXPECT_EQ(0, shm_unlink(name.c_str()));
}

TEST(UfifoLifetimeTest, AttachAndForceNeverMixGenerations)
{
    for (int iteration = 0; iteration < 50; iteration++)
        RunAttachForceRace();
}
