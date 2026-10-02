#include "ufifo_test_support.hpp"

class UfifoRoleTest : public ::testing::Test {};

TEST_F(UfifoRoleTest, RejectsInvalidRole)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.role = UFIFO_ROLE_MAX;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.max_users = 1;

    std::string name = GenerateName("invalid_role");
    ufifo_t *fifo = nullptr;
    EXPECT_EQ(-EINVAL, ufifo_open(name.c_str(), &init, &fifo));
    EXPECT_EQ(nullptr, fifo);
}

TEST_F(UfifoRoleTest, ProducerRoleRejectsReadOperations)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.role = UFIFO_ROLE_PRODUCER;
    init.alloc.size = 128;
    init.alloc.force = 1;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;

    std::string name = GenerateName("role_producer");
    ufifo_t *fifo = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &fifo));
    ASSERT_NE(nullptr, fifo);

    /* Producer must not take a consumer slot */
    EXPECT_EQ(0U, fifo->ctrl->num_users);

    /* Write operation succeeds */
    char write_buf[] = "hello";
    EXPECT_EQ(static_cast<ssize_t>(sizeof(write_buf)), ufifo_put(fifo, write_buf, sizeof(write_buf)));

    /* Read and peek operations must fail with -EPERM */
    char read_buf[64] = {};
    errno = 0;
    EXPECT_EQ(-EPERM, ufifo_get(fifo, read_buf, sizeof(read_buf)));
    EXPECT_EQ(EPERM, errno);

    errno = 0;
    EXPECT_EQ(-EPERM, ufifo_peek(fifo, read_buf, sizeof(read_buf)));
    EXPECT_EQ(EPERM, errno);

    errno = 0;
    EXPECT_EQ(-EPERM, ufifo_skip(fifo));
    EXPECT_EQ(EPERM, errno);

    errno = 0;
    EXPECT_EQ(-EPERM, ufifo_peek_len(fifo));
    EXPECT_EQ(EPERM, errno);

    EXPECT_EQ(0, ufifo_destroy(fifo));
}

TEST_F(UfifoRoleTest, ConsumerRoleRejectsWriteOperations)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.role = UFIFO_ROLE_PRODUCER;
    init.alloc.size = 128;
    init.alloc.force = 1;
    init.alloc.max_users = 2;
    init.alloc.data_mode = UFIFO_DATA_SHARED;

    std::string name = GenerateName("role_consumer");
    ufifo_t *producer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &producer));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    attach.role = UFIFO_ROLE_CONSUMER;
    ufifo_t *consumer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &consumer));
    ASSERT_NE(nullptr, consumer);

    /* Consumer must register one slot */
    EXPECT_EQ(1U, consumer->ctrl->num_users);

    /* Consumer write operations must fail with -EPERM */
    char write_buf[] = "data";
    errno = 0;
    EXPECT_EQ(-EPERM, ufifo_put(consumer, write_buf, sizeof(write_buf)));
    EXPECT_EQ(EPERM, errno);

    errno = 0;
    EXPECT_EQ(-EPERM, ufifo_put_block(consumer, write_buf, sizeof(write_buf)));
    EXPECT_EQ(EPERM, errno);

    errno = 0;
    EXPECT_EQ(-EPERM, ufifo_put_timeout(consumer, write_buf, sizeof(write_buf), 10));
    EXPECT_EQ(EPERM, errno);

    /* Producer writes and consumer reads successfully */
    EXPECT_EQ(static_cast<ssize_t>(sizeof(write_buf)), ufifo_put(producer, write_buf, sizeof(write_buf)));
    char read_buf[64] = {};
    EXPECT_EQ(static_cast<ssize_t>(sizeof(write_buf)), ufifo_get(consumer, read_buf, sizeof(read_buf)));
    EXPECT_STREQ(write_buf, read_buf);

    EXPECT_EQ(0, ufifo_close(consumer));
    EXPECT_EQ(0, ufifo_destroy(producer));
}

TEST_F(UfifoRoleTest, SharedProducerDoesNotSelfBlock)
{
    ufifo_init_t init = {};
    init.opt = UFIFO_OPT_ALLOC;
    init.role = UFIFO_ROLE_PRODUCER;
    init.alloc.size = 64;
    init.alloc.force = 1;
    init.alloc.lock = UFIFO_LOCK_NONE;
    init.alloc.data_mode = UFIFO_DATA_SHARED;
    init.alloc.max_users = 1;

    std::string name = GenerateName("shared_no_self_block");
    ufifo_t *producer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &producer));

    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    attach.role = UFIFO_ROLE_CONSUMER;
    ufifo_t *consumer = nullptr;
    ASSERT_EQ(0, ufifo_open(name.c_str(), &attach, &consumer));

    /* Write 32 bytes and consumer reads it */
    char chunk[32] = {};
    EXPECT_EQ(32, ufifo_put(producer, chunk, sizeof(chunk)));
    EXPECT_EQ(32, ufifo_get(consumer, chunk, sizeof(chunk)));

    /* Write another 32 bytes and consumer reads it */
    EXPECT_EQ(32, ufifo_put(producer, chunk, sizeof(chunk)));
    EXPECT_EQ(32, ufifo_get(consumer, chunk, sizeof(chunk)));

    /*
     * Buffer size is 64. Total written = 64 bytes.
     * With pure PRODUCER, producer out stays aligned with consumer progress.
     * Producer can continue to write without needing any artificial out advancement!
     */
    EXPECT_EQ(32, ufifo_put(producer, chunk, sizeof(chunk)));
    EXPECT_EQ(32, ufifo_get(consumer, chunk, sizeof(chunk)));

    EXPECT_EQ(0, ufifo_close(consumer));
    EXPECT_EQ(0, ufifo_destroy(producer));
}
