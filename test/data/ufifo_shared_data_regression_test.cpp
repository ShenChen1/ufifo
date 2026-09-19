#include "ufifo_test_support.hpp"

TEST_F(EdgeCaseTest, SharedModePutRespectsMinOut)
{
    std::string name = GenerateName("mpsc_minout");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    ufifo_t *fast_reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fast_reader));

    ufifo_t *slow_reader = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &slow_reader));

    char original[120];
    memset(original, 0xAA, sizeof(original));
    ASSERT_EQ(120, ufifo_put(fast_reader, original, sizeof(original)));

    char fast_output[120] = {};
    ASSERT_EQ(120, ufifo_get(fast_reader, fast_output, sizeof(fast_output)));

    char oversized[200];
    memset(oversized, 0xBB, sizeof(oversized));
    EXPECT_EQ(-EAGAIN, ufifo_put(fast_reader, oversized, sizeof(oversized)));

    char fitting[100];
    memset(fitting, 0xCC, sizeof(fitting));
    EXPECT_EQ(100, ufifo_put(fast_reader, fitting, sizeof(fitting)));

    char slow_output[120] = {};
    ASSERT_EQ(120, ufifo_get(slow_reader, slow_output, sizeof(slow_output)));
    EXPECT_EQ(0, memcmp(slow_output, original, sizeof(original)));

    EXPECT_EQ(0, ufifo_close(slow_reader));
    EXPECT_EQ(0, ufifo_destroy(fast_reader));
}

TEST_F(EdgeCaseTest, SharedModeNoUnsignedOverflow)
{
    std::string name = GenerateName("mpsc_nooverflow");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_THREAD;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 2;

    ufifo_t *fast_reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fast_reader));

    ufifo_t *slow_reader = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &slow_reader));

    char data[128];
    char output[128];
    memset(data, 0xAB, sizeof(data));
    size_t total_put = 0;
    for (int iteration = 0; iteration < 10; iteration++) {
        const ssize_t result = ufifo_put(fast_reader, data, sizeof(data));
        if (result <= 0)
            break;
        total_put += static_cast<size_t>(result);
        ASSERT_EQ(result, ufifo_get(fast_reader, output, sizeof(output)));
    }
    EXPECT_LE(total_put, 256U);

    size_t total_read = 0;
    while (total_read < total_put) {
        const ssize_t result = ufifo_get(slow_reader, output, sizeof(output));
        if (result <= 0)
            break;
        total_read += static_cast<size_t>(result);
    }
    EXPECT_EQ(total_put, total_read);

    EXPECT_EQ(0, ufifo_close(slow_reader));
    EXPECT_EQ(0, ufifo_destroy(fast_reader));
}
