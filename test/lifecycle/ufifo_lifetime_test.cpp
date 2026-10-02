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
        EXPECT_EQ(128, ufifo_size(replacement));
        if (attach_ret == 0) {
            EXPECT_EQ(128, ufifo_size(attached));
            EXPECT_EQ(0, ufifo_close(attached));
        } else {
            EXPECT_EQ(nullptr, attached);
        }
        EXPECT_EQ(0, ufifo_destroy(replacement));
    } else {
        ASSERT_EQ(0, attach_ret);
        EXPECT_EQ(nullptr, replacement);
        EXPECT_EQ(64, ufifo_size(attached));
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

TEST(UfifoLifetimeTest, ForceReplacesAbandonedObject)
{
    const std::string name = GenerateName("force_pre_header");
    const int fd = shm_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(0, close(fd));

    ufifo_init_t force = MakeAllocOptions();
    ufifo_t *replacement = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &force, &replacement));
    ASSERT_NE(nullptr, replacement);
    EXPECT_EQ(0, ufifo_destroy(replacement));
}

TEST(UfifoLifetimeTest, ProcessIdentityCacheTracksFork)
{
    ASSERT_EQ(0, __ufifo_process_identity_init());
    EXPECT_EQ(getpid(), __ufifo_process_pid());

    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0)
        _exit(__ufifo_process_pid() == getpid() ? 0 : 1);

    ChildProcess child(pid);
    int status = 0;
    TestDeadline child_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, child.WaitUntil(child_deadline, &status));
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(0, WEXITSTATUS(status));
    EXPECT_EQ(getpid(), __ufifo_process_pid());
}

TEST(UfifoLifetimeTest, ForkInheritedHandleIsRejected)
{
    const std::string name = GenerateName("fork_inherited");
    ufifo_init_t init = MakeAllocOptions();
    init.alloc.max_users = 1;
    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));

    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        char value = 'x';
        errno = 0;
        const bool rejected = ufifo_reset(owner) == -ECHILD && errno == ECHILD
                              && ufifo_size(owner) == -ECHILD && errno == ECHILD
                              && ufifo_len(owner) == -ECHILD && errno == ECHILD
                              && ufifo_skip(owner) == -ECHILD && errno == ECHILD
                              && ufifo_put(owner, &value, sizeof(value)) == -ECHILD
                              && ufifo_destroy(owner) == -ECHILD && ufifo_close(owner) == -ECHILD;
        _exit(rejected ? 0 : 1);
    }

    ChildProcess child(pid);
    int status = 0;
    TestDeadline child_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, child.WaitUntil(child_deadline, &status));
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *client = nullptr;
    EXPECT_EQ(-ENOSPC, ufifo_open(name.c_str(), &attach, &client));
    EXPECT_EQ(nullptr, client);

    char input = 'p';
    char output = 0;
    EXPECT_EQ(1, ufifo_put(owner, &input, sizeof(input)));
    EXPECT_EQ(1, ufifo_get(owner, &output, sizeof(output)));
    EXPECT_EQ(input, output);
    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoLifetimeTest, ActiveAttachPreventsDestroy)
{
    const std::string name = GenerateName("destroy_busy");
    ufifo_t *owner = CreateFifo(name);
    ASSERT_NE(nullptr, owner);

    TestPipe ready_pipe;
    TestPipe exit_pipe;
    ASSERT_EQ(0, TestPipe::Create(&ready_pipe));
    ASSERT_EQ(0, TestPipe::Create(&exit_pipe));

    const pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        ready_pipe.CloseRead();
        exit_pipe.CloseWrite();
        ufifo_init_t attach = {};
        attach.opt = UFIFO_OPT_ATTACH;
        ufifo_t *client = nullptr;
        const char status = ufifo_open(name.c_str(), &attach, &client) == 0 ? '1' : '0';
        (void)ready_pipe.WriteByte(status);
        char signal;
        TestDeadline exit_deadline(TEST_PROCESS_TIMEOUT);
        const int signal_result = exit_pipe.ReadByteUntil(exit_deadline, &signal);
        _exit(status == '1' && signal_result == 0 ? 0 : 1);
    }

    ChildProcess child(pid);
    ready_pipe.CloseWrite();
    exit_pipe.CloseRead();
    char status = '0';
    TestDeadline ready_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, ready_pipe.ReadByteUntil(ready_deadline, &status));
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

    ASSERT_EQ(0, exit_pipe.WriteByte('x'));
    int child_status = 0;
    TestDeadline child_deadline(TEST_PROCESS_TIMEOUT);
    ASSERT_EQ(0, child.WaitUntil(child_deadline, &child_status));
    EXPECT_TRUE(WIFEXITED(child_status));
    EXPECT_EQ(0, WEXITSTATUS(child_status));
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

TEST(UfifoLifetimeTest, ForceReplacesObjectRegardlessOfLayout)
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
    ASSERT_EQ(0, ufifo_open(name.c_str(), &force, &replacement));
    ASSERT_NE(nullptr, replacement);
    EXPECT_EQ(0, ufifo_destroy(replacement));
}

TEST(UfifoLifetimeTest, AttachAndForceNeverMixGenerations)
{
    for (int iteration = 0; iteration < 50; iteration++)
        RunAttachForceRace();
}

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
