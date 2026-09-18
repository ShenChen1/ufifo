#include "ufifo_test_support.hpp"

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
    EXPECT_EQ(0u, ufifo_len(fifo));
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
    EXPECT_EQ(0u, ufifo_len(reader));

    ufifo_close(replacement);
    ufifo_destroy(reader);
}

TEST_F(EdgeCaseTest, ProcessLockCrashRecovery)
{
    std::string name = GenerateName("ec_crash");
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.alloc.size = 256;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_PROCESS;
    init.alloc.data_mode = UFIFO_DATA_SOLE;
    init.alloc.max_users = 2;

    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));

    pid_t pid = fork();
    if (pid == 0) {
        int val = 999;
        ufifo_put(fifo, &val, sizeof(val));
        _exit(0); // Exit abandoning the lock/handle mapping
    } else {
        ASSERT_GT(pid, 0);
        int status;
        waitpid(pid, &status, 0);

        int out = 0;
        unsigned int ret = ufifo_get(fifo, &out, sizeof(out));
        if (ret > 0) {
            EXPECT_EQ(999, out);
        }
    }
    ufifo_destroy(fifo);
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

// Issue 1: Fast consumer's put overwrites slow consumer's unconsumed data
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

    ufifo_t *h1 = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &h1));

    ufifo_t *h2 = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &h2));

    // Step 1: H1 puts 120 bytes of 0xAA → in=120
    char buf_a[120];
    memset(buf_a, 0xAA, sizeof(buf_a));
    ASSERT_EQ(120u, ufifo_put(h1, buf_a, sizeof(buf_a)));

    // Step 2: H1 gets 120 bytes → H1.out=120, H2.out=0
    char out1[120] = {};
    ASSERT_EQ(120u, ufifo_get(h1, out1, sizeof(out1)));

    // Step 3: H1 tries to put 200 bytes
    // own_out unused  = 256 - (120-120) = 256 → WRONG (would pass)
    // min_out unused  = 256 - (120-0)   = 136 → CORRECT (200 > 136, fails)
    char buf_b[200];
    memset(buf_b, 0xBB, sizeof(buf_b));
    unsigned int ret = ufifo_put(h1, buf_b, sizeof(buf_b));
    EXPECT_EQ(0u, ret) << "Put 200B should fail: only 136B available (min_out=0)";

    // Step 4: A smaller put (within 136B limit) should succeed
    char buf_c[100];
    memset(buf_c, 0xCC, sizeof(buf_c));
    ret = ufifo_put(h1, buf_c, sizeof(buf_c));
    EXPECT_EQ(100u, ret) << "Put 100B should succeed: fits within 136B available";

    // Step 5: H2 reads original data — must NOT be corrupted
    char out2[120] = {};
    ASSERT_EQ(120u, ufifo_get(h2, out2, sizeof(out2)));
    EXPECT_EQ(0, memcmp(out2, buf_a, sizeof(buf_a))) << "H2's data must not be corrupted by H1's put";

    ufifo_close(h2);
    ufifo_destroy(h1);
}

// Issue 2: Unsigned overflow causes impossible put after repeated put+get cycles
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

    ufifo_t *h1 = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &h1));

    ufifo_t *h2 = nullptr;
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &h2));

    // H1 repeatedly puts 128B then gets 128B. H2 never gets.
    // Without fix: in keeps growing, unsigned overflow allows infinite puts
    // With fix: total put capped at 256 (buffer_size - (in - min_out))
    char data[128];
    memset(data, 0xAB, sizeof(data));
    char tmp[128];

    unsigned int total_put = 0;
    for (int i = 0; i < 10; i++) {
        unsigned int ret = ufifo_put(h1, data, sizeof(data));
        if (ret == 0)
            break;
        total_put += ret;
        ufifo_get(h1, tmp, sizeof(tmp));
    }

    // With fix: total_put = 256 (two puts of 128, then blocked)
    // Without fix: total_put = 1280 (all 10 puts succeed)
    EXPECT_LE(total_put, 256u) << "Total put should not exceed buffer size relative to slowest consumer";

    // H2 should be able to read all data that was put
    unsigned int total_got = 0;
    while (total_got < total_put) {
        unsigned int ret = ufifo_get(h2, tmp, sizeof(tmp));
        if (ret == 0)
            break;
        total_got += ret;
    }
    EXPECT_EQ(total_put, total_got) << "H2 should read exactly the amount of data that was put";

    ufifo_close(h2);
    ufifo_destroy(h1);
}

// Regression: reader close must wake a blocked writer in SHARED mode
