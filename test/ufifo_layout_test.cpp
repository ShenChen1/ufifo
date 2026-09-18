#include "ufifo_test_support.hpp"

TEST(UfifoLayoutTest, RejectsIncompatibleSharedLayout)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    const std::string name = GenerateName("layout_abi");
    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));

    owner->ctrl->layout_abi = UFIFO_LAYOUT_ABI - 1;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *client = nullptr;
    EXPECT_EQ(-EPROTO, ufifo_open(name.c_str(), &attach, &client));
    EXPECT_EQ(nullptr, client);

    owner->ctrl->layout_abi = UFIFO_LAYOUT_ABI;
    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoLayoutTest, RejectsInvalidDataOffset)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    const std::string name = GenerateName("layout_offset");
    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));

    const size_t data_offset = owner->ctrl->data_offset;
    owner->ctrl->data_offset += 64;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *client = nullptr;
    EXPECT_EQ(-EPROTO, ufifo_open(name.c_str(), &attach, &client));
    EXPECT_EQ(nullptr, client);

    owner->ctrl->data_offset = data_offset;
    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoLayoutTest, RejectsMaxUsersLayoutOverflow)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    const std::string name = GenerateName("layout_users_overflow");
    ufifo_t *owner = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &owner));

    owner->ctrl->max_users = SIZE_MAX;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *client = nullptr;
    EXPECT_EQ(-EPROTO, ufifo_open(name.c_str(), &attach, &client));
    EXPECT_EQ(nullptr, client);

    owner->ctrl->max_users = init.alloc.max_users;
    EXPECT_EQ(0, ufifo_destroy(owner));
}

TEST(UfifoLayoutTest, RejectsBackingSizeOutsideOffT)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = (static_cast<size_t>(INT64_MAX) / 2) + 2;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 1;

    const std::string name = GenerateName("layout_overflow");
    ufifo_t *owner = nullptr;
    EXPECT_EQ(-EOVERFLOW, ufifo_open(name.c_str(), &init, &owner));
    EXPECT_EQ(nullptr, owner);
    errno = 0;
    EXPECT_EQ(-1, shm_open(name.c_str(), O_RDWR, 0));
    EXPECT_EQ(ENOENT, errno);
}
