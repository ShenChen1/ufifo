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
