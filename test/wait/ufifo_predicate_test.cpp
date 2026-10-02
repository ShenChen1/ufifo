#include "ufifo_test_support.hpp"

extern "C" {
#include "ufifo_predicate.h"
}

namespace {

constexpr size_t kPredicateCapacity = 64;

size_t RecordLength(uint8_t *first, size_t, uint8_t *)
{
    return *first;
}

class UfifoPredicateTest : public ::testing::TestWithParam<ufifo_data_mode_e> {
  protected:
    void SetUp() override
    {
        name_ = GenerateName("predicate");
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = kPredicateCapacity;
        init.alloc.max_users = 2;
        init.alloc.force = 1;
        init.alloc.lock = UFIFO_LOCK_NONE;
        init.alloc.data_mode = GetParam();
        ASSERT_EQ(0, ufifo_open(name_.c_str(), &init, &fifo_));
    }

    void TearDown() override
    {
        if (fifo_ != nullptr) {
            EXPECT_EQ(0, ufifo_destroy(fifo_));
        }
    }

    std::string name_;
    ufifo_t *fifo_ = nullptr;
};

TEST_P(UfifoPredicateTest, EmptyPredicatesOnlyReadState)
{
    EXPECT_EQ(0U, __ufifo_rx_data_len_fast(fifo_));
    EXPECT_EQ(kPredicateCapacity, __ufifo_tx_available_fast(fifo_));
    const uint32_t rx_epoch = __ufifo_wait_arm(__ufifo_rx_wait_word(fifo_));
    const uint32_t tx_epoch = __ufifo_wait_arm(__ufifo_tx_wait_word(fifo_));
    EXPECT_EQ(0U, __ufifo_rx_data_len_for_wait(fifo_));
    EXPECT_EQ(0U, __ufifo_rx_data_len_after_arm(fifo_));
    EXPECT_EQ(kPredicateCapacity, __ufifo_tx_available_after_arm(fifo_));
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(fifo_->kfifo.in));
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(fifo_->kfifo.out));
    EXPECT_EQ(rx_epoch, ufifo_atomic_load_acquire(__ufifo_rx_wait_word(fifo_)));
    EXPECT_EQ(tx_epoch, ufifo_atomic_load_acquire(__ufifo_tx_wait_word(fifo_)));
}

TEST_P(UfifoPredicateTest, FullBufferHasDataAndNoWriteSpace)
{
    char data[kPredicateCapacity] = {};
    ASSERT_EQ(static_cast<ssize_t>(sizeof(data)), ufifo_put(fifo_, data, sizeof(data)));
    EXPECT_EQ(1U, __ufifo_rx_data_len_fast(fifo_));
    EXPECT_EQ(0U, __ufifo_tx_available_fast(fifo_));
    __ufifo_wait_arm(__ufifo_rx_wait_word(fifo_));
    __ufifo_wait_arm(__ufifo_tx_wait_word(fifo_));
    EXPECT_EQ(1U, __ufifo_rx_data_len_after_arm(fifo_));
    EXPECT_EQ(0U, __ufifo_tx_available_after_arm(fifo_));
    EXPECT_EQ(-EAGAIN, ufifo_put(fifo_, data, 1));
    EXPECT_EQ(1, ufifo_get(fifo_, data, 1));
    EXPECT_EQ(1U, __ufifo_tx_available_fast(fifo_));
}

TEST_P(UfifoPredicateTest, RecordLengthAndSmallBufferFailureArePreserved)
{
    fifo_->hook.recsize = RecordLength;
    char record[12] = { 12 };
    ASSERT_EQ(static_cast<ssize_t>(sizeof(record)), ufifo_put(fifo_, record, sizeof(record)));
    EXPECT_EQ(sizeof(record), __ufifo_rx_data_len_fast(fifo_));
    __ufifo_wait_arm(__ufifo_rx_wait_word(fifo_));
    EXPECT_EQ(sizeof(record), __ufifo_rx_data_len_after_arm(fifo_));
    char output[12] = {};
    EXPECT_EQ(-ENOBUFS, ufifo_get(fifo_, output, 4));
    EXPECT_EQ(sizeof(record), __ufifo_rx_data_len_fast(fifo_));
    EXPECT_EQ(static_cast<ssize_t>(sizeof(output)), ufifo_get(fifo_, output, sizeof(output)));
    EXPECT_EQ(0, memcmp(record, output, sizeof(record)));
    EXPECT_EQ(0U, __ufifo_rx_data_len_fast(fifo_));
    EXPECT_EQ(kPredicateCapacity, __ufifo_tx_available_fast(fifo_));
}

TEST_P(UfifoPredicateTest, IndexWrapPreservesCapacityAndReadiness)
{
    const size_t start = SIZE_MAX - 7;
    ufifo_atomic_store_release(fifo_->kfifo.in, start);
    ufifo_atomic_store_release(fifo_->kfifo.out, start);
    ufifo_atomic_store_release(&fifo_->ctrl->cached_min_out, start);
    char data[16] = {};
    ASSERT_EQ(static_cast<ssize_t>(sizeof(data)), ufifo_put(fifo_, data, sizeof(data)));
    EXPECT_EQ(8U, ufifo_atomic_load_acquire(fifo_->kfifo.in));
    __ufifo_wait_arm(__ufifo_rx_wait_word(fifo_));
    __ufifo_wait_arm(__ufifo_tx_wait_word(fifo_));
    EXPECT_EQ(1U, __ufifo_rx_data_len_after_arm(fifo_));
    EXPECT_EQ(kPredicateCapacity - sizeof(data), __ufifo_tx_available_after_arm(fifo_));
    EXPECT_EQ(static_cast<ssize_t>(sizeof(data)), ufifo_get(fifo_, data, sizeof(data)));
    EXPECT_EQ(0U, __ufifo_rx_data_len_fast(fifo_));
    EXPECT_EQ(kPredicateCapacity, __ufifo_tx_available_fast(fifo_));
}

TEST_P(UfifoPredicateTest, SharedCapacityReadDoesNotRefreshCachedMinimum)
{
    if (GetParam() != UFIFO_DATA_SHARED)
        GTEST_SKIP() << "Cached minimum is only a shared-mode predicate";
    ufifo_init_t attach = {};
    attach.opt = UFIFO_OPT_ATTACH;
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, ufifo_open(name_.c_str(), &attach, &reader));
    std::unique_ptr<ufifo_t, decltype(&ufifo_close)> reader_guard(reader, ufifo_close);
    char data[12] = {};
    ASSERT_EQ(static_cast<ssize_t>(sizeof(data)), ufifo_put(fifo_, data, sizeof(data)));
    ASSERT_EQ(static_cast<ssize_t>(sizeof(data)), ufifo_get(fifo_, data, sizeof(data)));
    ufifo_atomic_store_release(reader->kfifo.out, sizeof(data));
    __ufifo_wait_arm(__ufifo_tx_wait_word(fifo_));
    EXPECT_EQ(kPredicateCapacity - sizeof(data), __ufifo_tx_available_fast(fifo_));
    EXPECT_EQ(kPredicateCapacity - sizeof(data), __ufifo_tx_available_after_arm(fifo_));
    EXPECT_EQ(0U, ufifo_atomic_load_acquire(&fifo_->ctrl->cached_min_out));
    EXPECT_TRUE(__ufifo_update_cached_min_out(fifo_));
    EXPECT_EQ(kPredicateCapacity, __ufifo_tx_available_fast(fifo_));
}

INSTANTIATE_TEST_SUITE_P(Modes, UfifoPredicateTest, ::testing::Values(UFIFO_DATA_SOLE, UFIFO_DATA_SHARED));

} // namespace
