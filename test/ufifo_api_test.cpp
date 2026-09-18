#include "ufifo_test_support.hpp"

class UfifoApiTest : public ::testing::Test {};

TEST_F(UfifoApiTest, GetVersion)
{
    const char *version = ufifo_get_version();
    EXPECT_NE(nullptr, version);
    EXPECT_GT(strlen(version), 0);
}

TEST_F(UfifoApiTest, OpenWithNullName)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(nullptr, &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithNullInit)
{
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open("test", nullptr, &fifo));
}

TEST_F(UfifoApiTest, OpenWithInvalidOpt)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_MAX;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name = GenerateName("invalid_opt");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(name.c_str(), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithInvalidLock)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_MAX;
    init.alloc.max_users = 1;
    std::string name = GenerateName("invalid_lock");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(name.c_str(), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithZeroSize)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 0;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name = GenerateName("zero_size");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(name.c_str(), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithNullHandle)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name = GenerateName("null_handle");
    EXPECT_NE(0, ufifo_open(name.c_str(), &init, nullptr));
}

TEST_F(UfifoApiTest, OpenWithEmptyName)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open("", &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithMaxLengthName)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name = GenerateName("max_name");
    name.append(UFIFO_NAME_MAX - name.size(), 'x');
    ufifo_t *fifo = nullptr;

    ASSERT_EQ(UFIFO_NAME_MAX, name.size());
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    EXPECT_EQ(0, ufifo_destroy(fifo));
    errno = 0;
    EXPECT_EQ(-1, shm_open(name.c_str(), O_RDWR, 0));
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(UfifoApiTest, OpenWithTooLongName)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    std::string name(UFIFO_NAME_MAX + 1, 'x');
    ufifo_t *fifo = nullptr;

    EXPECT_EQ(-ENAMETOOLONG, ufifo_open(name.c_str(), &init, &fifo));
    EXPECT_EQ(nullptr, fifo);
}

TEST_F(UfifoApiTest, OpenWithInvalidDataMode)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.data_mode = UFIFO_DATA_MAX;
    init.alloc.max_users = 1;
    std::string name = GenerateName("invalid_mode");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(name.c_str(), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithZeroMaxUsers)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 0;
    std::string name = GenerateName("zero_users");
    ufifo_t *fifo = nullptr;
    EXPECT_NE(0, ufifo_open(name.c_str(), &init, &fifo));
}

TEST_F(UfifoApiTest, OpenWithTooManyUsers)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = UFIFO_MAX_NUM_USERS + 1;
    std::string name = GenerateName("sole_users_scm_limit");
    ufifo_t *fifo = nullptr;
    EXPECT_EQ(-EINVAL, ufifo_open(name.c_str(), &init, &fifo));
}

TEST_F(UfifoApiTest, AttachNonExistent)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ATTACH;
    ufifo_t *fifo = nullptr;
    EXPECT_EQ(-ENOENT, ufifo_open("nonexistent_fifo_xyz", &init, &fifo));
    EXPECT_EQ(nullptr, fifo);
}

// Version compatibility: mismatched major version should fail with -EPROTO
TEST_F(UfifoApiTest, VersionMismatchMajor)
{
    std::string name = GenerateName("ver_mismatch");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    /* The inherited mapping is shared, so the child can corrupt the fixed header directly. */
    pid_t pid = fork();
    if (pid == 0) {
        fifo->ctrl->ver.major = 0xDEAD;

        /* Now try to attach — should fail */
        ufifo_init_t att = {};
        att.opt = UFIFO_OPT_ATTACH;
        ufifo_t *h = nullptr;
        int ret = ufifo_open(name.c_str(), &att, &h);
        _exit(ret == -EPROTO ? 0 : 2);
    } else {
        ASSERT_GT(pid, 0);
        int status;
        waitpid(pid, &status, 0);
        EXPECT_TRUE(WIFEXITED(status));
        EXPECT_EQ(0, WEXITSTATUS(status)) << "Child should exit 0 (attach rejected with -EPROTO)";
    }

    ufifo_destroy(fifo);
}

// Construct a raw single shm object with a mismatched version.
TEST_F(UfifoApiTest, VersionMismatchViaRawShm)
{
    std::string name = GenerateName("ver_raw");
    const size_t mapping_size = 4096;
    int fd = shm_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(0, ftruncate(fd, mapping_size));
    void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    ASSERT_NE(MAP_FAILED, mapping);

    // Write a fake ufifo_version_t at offset 0 (matches ctrl layout)
    ufifo_version_t fake_ver = {};
    fake_ver.major = 99; // intentionally mismatched
    fake_ver.minor = 88;
    fake_ver.patch = 77;
    snprintf(fake_ver.version, sizeof(fake_ver.version), "v99.88.77-fake");
    auto *fake_ctrl = static_cast<ufifo_ctrl_t *>(mapping);
    memcpy(&fake_ctrl->ver, &fake_ver, sizeof(fake_ver));
    fake_ctrl->layout_abi = UFIFO_LAYOUT_ABI;
    fake_ctrl->init_done = true;

    munmap(mapping, mapping_size);

    // 3. Try ATTACH — version check should reject with -EPROTO
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ATTACH;
    ufifo_t *fifo = nullptr;
    EXPECT_EQ(-EPROTO, ufifo_open(name.c_str(), &init, &fifo));
    EXPECT_EQ(nullptr, fifo);

    shm_unlink(name.c_str());
}

// ufifo_get_version_info: NULL ver should return -EINVAL
TEST_F(UfifoApiTest, VersionInfoNullVer)
{
    EXPECT_EQ(-EINVAL, ufifo_get_version_info(nullptr, nullptr));

    std::string name = GenerateName("ver_nullver");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.max_users = 1;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    EXPECT_EQ(-EINVAL, ufifo_get_version_info(fifo, nullptr));
    ufifo_destroy(fifo);
}

// ufifo_get_version_info(NULL, &ver): returns library compile-time version
TEST_F(UfifoApiTest, VersionInfoLibQuery)
{
    ufifo_version_t ver = {};
    ASSERT_EQ(0, ufifo_get_version_info(nullptr, &ver));

    EXPECT_EQ(2U, ver.major);
    // version string must match ufifo_get_version()
    EXPECT_STREQ(ufifo_get_version(), ver.version);
    // version string must be non-empty
    EXPECT_GT(strlen(ver.version), 0u);
}

// ufifo_get_version_info(handle, &ver): returns version stamped in ctrl
TEST_F(UfifoApiTest, VersionInfoHandleMatchesLib)
{
    std::string name = GenerateName("ver_handle");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.max_users = 2;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    ufifo_version_t lib_ver = {};
    ufifo_version_t handle_ver = {};
    ASSERT_EQ(0, ufifo_get_version_info(nullptr, &lib_ver));
    ASSERT_EQ(0, ufifo_get_version_info(fifo, &handle_ver));

    // Same library created this handle, so versions must match
    EXPECT_EQ(lib_ver.major, handle_ver.major);
    EXPECT_EQ(lib_ver.minor, handle_ver.minor);
    EXPECT_EQ(lib_ver.patch, handle_ver.patch);
    EXPECT_STREQ(lib_ver.version, handle_ver.version);

    ufifo_destroy(fifo);
}

// ATTACH handle should also see the creator's version in ctrl
TEST_F(UfifoApiTest, VersionInfoAttachSeesCreatorVersion)
{
    std::string name = GenerateName("ver_attach");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    ufifo_t *creator = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &creator));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *client = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &client));

    ufifo_version_t creator_ver = {};
    ufifo_version_t client_ver = {};
    ASSERT_EQ(0, ufifo_get_version_info(creator, &creator_ver));
    ASSERT_EQ(0, ufifo_get_version_info(client, &client_ver));

    // Both should read the same version from shared memory ctrl
    EXPECT_EQ(creator_ver.major, client_ver.major);
    EXPECT_EQ(creator_ver.minor, client_ver.minor);
    EXPECT_EQ(creator_ver.patch, client_ver.patch);
    EXPECT_STREQ(creator_ver.version, client_ver.version);

    ufifo_close(client);
    ufifo_destroy(creator);
}

TEST_F(UfifoApiTest, Dump)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;

    std::string name = GenerateName("dump_test");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    int val = 42;
    ufifo_put(fifo, &val, sizeof(val));

    testing::internal::CaptureStdout();
    ufifo_dump(fifo);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_TRUE(output.find("=== ufifo_dump:") != std::string::npos);
    EXPECT_TRUE(output.find("offset: ") != std::string::npos);

    ufifo_destroy(fifo);
}

TEST_F(UfifoApiTest, PutOversized)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.max_users = 1;
    init.alloc.data_mode = UFIFO_DATA_SOLE;

    std::string name = GenerateName("oversized_test");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    unsigned int capacity = ufifo_size(fifo);
    std::vector<char> large_buf(capacity + 1, 'x');

    errno = 0;
    unsigned int written = ufifo_put_block(fifo, large_buf.data(), large_buf.size());
    EXPECT_EQ(0u, written);
    EXPECT_EQ(EMSGSIZE, errno);

    errno = 0;
    written = ufifo_put(fifo, large_buf.data(), large_buf.size());
    EXPECT_EQ(0u, written);
    EXPECT_EQ(EMSGSIZE, errno);

    errno = 0;
    written = ufifo_put_timeout(fifo, large_buf.data(), large_buf.size(), 100);
    EXPECT_EQ(0u, written);
    EXPECT_EQ(EMSGSIZE, errno);

    ufifo_destroy(fifo);
}

// =============================================================================
// 2. Base test suite class handling Parametrization
// =============================================================================
