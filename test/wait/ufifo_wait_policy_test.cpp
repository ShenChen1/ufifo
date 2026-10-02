#include "ufifo_test_support.hpp"

#include <tuple>

namespace {

constexpr size_t kCapacity = 64;
constexpr long kWriterTimeoutMs = 2000;
using WaitConfiguration = std::tuple<ufifo_data_mode_e, ufifo_lock_e>;

enum class CapacityPublisher { Get, Skip, Oldest, Newest, Reset, Close };

size_t OneByteRecord(uint8_t *, size_t, uint8_t *)
{
    return 1;
}

size_t ByteTag(uint8_t *first, size_t, uint8_t *)
{
    return *first;
}

class UfifoWaitPolicyTest : public ::testing::TestWithParam<WaitConfiguration> {
  protected:
    void SetUp() override
    {
        const std::string name = GenerateName("wait_policy");
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.role = UFIFO_ROLE_PRODUCER;
        init.alloc.size = kCapacity;
        init.alloc.max_users = 2;
        init.alloc.force = 1;
        init.alloc.data_mode = std::get<0>(GetParam());
        init.alloc.lock = std::get<1>(GetParam());
        init.hook.recsize = OneByteRecord;
        init.hook.rectag = ByteTag;
        ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &producer_));
        init.opt = UFIFO_OPT_ATTACH;
        init.role = UFIFO_ROLE_CONSUMER;
        ASSERT_EQ(0, ufifo_open(name.c_str(), &init, &consumer_));
    }

    void TearDown() override
    {
        if (consumer_ != nullptr) {
            EXPECT_EQ(0, ufifo_close(consumer_));
        }
        if (producer_ != nullptr) {
            EXPECT_EQ(0, ufifo_destroy(producer_));
        }
    }

    ssize_t FillBuffer()
    {
        char data[kCapacity];
        memset(data, 'a', sizeof(data));
        data[1] = 'b';
        data[kCapacity - 1] = 'b';
        return ufifo_put(producer_, data, sizeof(data));
    }

    ssize_t PublishCapacity(CapacityPublisher publisher)
    {
        char value = 0;
        switch (publisher) {
        case CapacityPublisher::Get:
            return ufifo_get(consumer_, &value, 1);
        case CapacityPublisher::Skip:
            return ufifo_skip(consumer_);
        case CapacityPublisher::Oldest:
            return ufifo_oldest(consumer_, 'b');
        case CapacityPublisher::Newest:
            return ufifo_newest(consumer_, 'b');
        case CapacityPublisher::Reset:
            return ufifo_reset(producer_);
        case CapacityPublisher::Close: {
            const int ret = ufifo_close(consumer_);
            if (ret == 0)
                consumer_ = nullptr;
            return ret;
        }
        }
        return -EINVAL;
    }

    void CheckPublisherWakesWriter(CapacityPublisher publisher)
    {
        ASSERT_EQ(static_cast<ssize_t>(kCapacity), FillBuffer());
        ssize_t writer_result = -EINPROGRESS;
        std::thread writer([&] {
            char value = 'x';
            writer_result = ufifo_put_timeout(producer_, &value, 1, kWriterTimeoutMs);
        });
        const bool armed = WaitForWaitWordArm(__ufifo_tx_wait_word(producer_));
        const ssize_t publish_result = armed ? PublishCapacity(publisher) : -ETIMEDOUT;
        writer.join();
        EXPECT_TRUE(armed);
        EXPECT_GE(publish_result, 0);
        EXPECT_EQ(1, writer_result);
        EXPECT_EQ(0U, ufifo_atomic_load_acquire(__ufifo_tx_wait_word(producer_)) & 1U);
    }

    ufifo_t *producer_ = nullptr;
    ufifo_t *consumer_ = nullptr;
};

TEST_P(UfifoWaitPolicyTest, GetPublishesCapacity)
{
    CheckPublisherWakesWriter(CapacityPublisher::Get);
}

TEST_P(UfifoWaitPolicyTest, SkipPublishesCapacity)
{
    CheckPublisherWakesWriter(CapacityPublisher::Skip);
}

TEST_P(UfifoWaitPolicyTest, OldestPublishesCapacity)
{
    CheckPublisherWakesWriter(CapacityPublisher::Oldest);
}

TEST_P(UfifoWaitPolicyTest, NewestPublishesCapacity)
{
    CheckPublisherWakesWriter(CapacityPublisher::Newest);
}

TEST_P(UfifoWaitPolicyTest, ProducerResetPublishesCapacity)
{
    CheckPublisherWakesWriter(CapacityPublisher::Reset);
}

TEST_P(UfifoWaitPolicyTest, SharedReaderClosePublishesCapacity)
{
    if (std::get<0>(GetParam()) == UFIFO_DATA_SOLE)
        GTEST_SKIP() << "Closing a sole reader does not consume queued data";
    CheckPublisherWakesWriter(CapacityPublisher::Close);
}

TEST_P(UfifoWaitPolicyTest, NotificationWithoutCapacityCannotCompleteWrite)
{
    ASSERT_EQ(static_cast<ssize_t>(kCapacity), FillBuffer());
    ssize_t writer_result = -EINPROGRESS;
    std::thread writer([&] {
        char value = 'x';
        writer_result = ufifo_put_timeout(producer_, &value, 1, 40);
    });
    const bool armed = WaitForWaitWordArm(__ufifo_tx_wait_word(producer_));
    if (armed)
        __ufifo_notify_writers(producer_);
    writer.join();
    EXPECT_TRUE(armed);
    EXPECT_EQ(-ETIMEDOUT, writer_result);
    char value = 0;
    EXPECT_EQ(1, ufifo_get(consumer_, &value, 1));
    EXPECT_EQ('a', value);
}

INSTANTIATE_TEST_SUITE_P(ModesAndLocks,
                         UfifoWaitPolicyTest,
                         ::testing::Combine(::testing::Values(UFIFO_DATA_SOLE, UFIFO_DATA_SHARED),
                                            ::testing::Values(UFIFO_LOCK_NONE, UFIFO_LOCK_THREAD, UFIFO_LOCK_PROCESS)));

} // namespace
