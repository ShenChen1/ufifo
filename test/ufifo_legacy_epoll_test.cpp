#include "ufifo_test_support.hpp"

class EpollTest : public ::testing::TestWithParam<DataFormat> {
  protected:
    std::unique_ptr<UfifoTestAdapter> adapter_;
    std::string name_;

    void SetUp() override
    {
        name_ = GenerateName("epoll");
        adapter_ = std::make_unique<UfifoTestAdapter>(GetParam(), DataMode::SHARED, UFIFO_LOCK_THREAD, name_);
    }
};

std::string PrintDataFormat(const testing::TestParamInfo<DataFormat> &info)
{
    switch (info.param) {
    case DataFormat::BYTESTREAM:
        return "Byte";
    case DataFormat::RECORD:
        return "Record";
    case DataFormat::TAG:
        return "Tag";
    }
    return "Unknown";
}

// --- Happy path: ufifo_get_fd returns valid fd and is idempotent ---
TEST_P(EpollTest, GetFdIdempotent)
{
    ASSERT_EQ(0, adapter_->Create(1024, UFIFO_LOCK_THREAD, 2));

    ufifo_t *h = adapter_->GetMainHandle();
    int fd = ufifo_get_rx_fd(h);
    EXPECT_GE(fd, 0);
    EXPECT_EQ(fd, ufifo_get_rx_fd(h));
}

// --- Happy path: empty FIFO does not trigger epoll ---
TEST_P(EpollTest, NoEventWhenEmpty)
{
    ASSERT_EQ(0, adapter_->Create(1024, UFIFO_LOCK_THREAD, 2));

    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, adapter_->Attach(&reader));

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    int fd = ufifo_get_rx_fd(reader);
    ASSERT_GE(fd, 0);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev));

    struct epoll_event events[1];
    EXPECT_EQ(0, epoll_wait(epfd, events, 1, 50));

    close(epfd);
}

// --- Happy path: put triggers epoll on a single consumer ---
TEST_P(EpollTest, SingleConsumerWakeup)
{
    ASSERT_EQ(0, adapter_->Create(1024, UFIFO_LOCK_THREAD, 2));

    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, adapter_->Attach(&reader));

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    int fd = ufifo_get_rx_fd(reader);
    ASSERT_GE(fd, 0);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev));

    // Put via adapter (writer = handle[0])
    EXPECT_GT(adapter_->PutValue(adapter_->GetMainHandle(), 42), 0);

    struct epoll_event events[1];
    EXPECT_EQ(1, epoll_wait(epfd, events, 1, 1000));

    ufifo_drain_rx_fd(reader);

    int out = 0;
    EXPECT_GT(adapter_->GetValue(reader, out), 0);
    EXPECT_EQ(42, out);

    // Writer must also consume to advance its own out pointer in SHARED mode
    int dummy = 0;
    adapter_->GetValue(adapter_->GetMainHandle(), dummy);

    close(epfd);
}

// --- Happy path: multicast — all consumers are woken by a single put ---
TEST_P(EpollTest, SharedModeMulticast)
{
    const int num_readers = 2;
    ASSERT_EQ(0, adapter_->Create(1024, UFIFO_LOCK_THREAD, num_readers + 1));

    ufifo_t *readers[num_readers] = {};
    int fds[num_readers] = {};

    for (int i = 0; i < num_readers; i++) {
        ASSERT_EQ(0, adapter_->Attach(&readers[i]));
        fds[i] = ufifo_get_rx_fd(readers[i]);
        ASSERT_GE(fds[i], 0);
    }

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    for (int i = 0; i < num_readers; i++) {
        struct epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.u32 = i;
        ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i], &ev));
    }

    // Writer puts
    EXPECT_GT(adapter_->PutValue(adapter_->GetMainHandle(), 999), 0);

    // All readers should wake up
    struct epoll_event events[num_readers];
    int nfds = epoll_wait(epfd, events, num_readers, 1000);
    EXPECT_EQ(num_readers, nfds);

    std::vector<bool> ready(num_readers, false);
    for (int i = 0; i < nfds; i++) {
        ready[events[i].data.u32] = true;
    }
    for (int i = 0; i < num_readers; i++) {
        EXPECT_TRUE(ready[i]) << "reader " << i << " was not woken";
    }

    // Each reader should independently get the same value
    for (int i = 0; i < num_readers; i++) {
        ufifo_drain_rx_fd(readers[i]);
        int out = 0;
        EXPECT_GT(adapter_->GetValue(readers[i], out), 0);
        EXPECT_EQ(999, out);
    }

    // Writer consumes its own copy
    int dummy = 0;
    adapter_->GetValue(adapter_->GetMainHandle(), dummy);

    close(epfd);
}

// --- Happy path: multiple sequential puts, consumer drains all ---
TEST_P(EpollTest, MultiplePutDrainAll)
{
    const int count = 10;
    ASSERT_EQ(0, adapter_->Create(4096, UFIFO_LOCK_THREAD, 2));

    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, adapter_->Attach(&reader));

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    int fd = ufifo_get_rx_fd(reader);
    ASSERT_GE(fd, 0);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev));

    ufifo_t *writer = adapter_->GetMainHandle();
    for (int i = 0; i < count; i++) {
        EXPECT_GT(adapter_->PutValue(writer, i), 0);
        // Writer consumes to keep its out advancing
        int wd = 0;
        adapter_->GetValue(writer, wd);
    }

    // Wait for any notification
    struct epoll_event events[1];
    EXPECT_GE(epoll_wait(epfd, events, 1, 1000), 1);
    ufifo_drain_rx_fd(reader);

    // Reader drains all
    int received = 0;
    int out = 0;
    while (adapter_->GetValue(reader, out) > 0) {
        EXPECT_EQ(received, out);
        received++;
    }
    EXPECT_EQ(count, received);

    close(epfd);
}

// --- Happy path: concurrent producer thread + epoll consumer thread ---
TEST_P(EpollTest, ConcurrentProducerEpollConsumer)
{
    const int msg_count = 200;
    ASSERT_EQ(0, adapter_->Create(4096, UFIFO_LOCK_THREAD, 2));

    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, adapter_->Attach(&reader));

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    int fd = ufifo_get_rx_fd(reader);
    ASSERT_GE(fd, 0);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev));

    std::atomic<int> consumed{ 0 };

    // Consumer thread: epoll loop
    std::thread consumer([&]() {
        while (consumed.load(std::memory_order_relaxed) < msg_count) {
            struct epoll_event evts[1];
            int n = epoll_wait(epfd, evts, 1, 100);
            if (n <= 0)
                continue;
            ufifo_drain_rx_fd(reader);

            int out = 0;
            while (adapter_->GetValue(reader, out) > 0) {
                consumed.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    // Producer thread: write via adapter
    ufifo_t *writer = adapter_->GetMainHandle();
    std::thread producer([&]() {
        for (int i = 0; i < msg_count; i++) {
            while (adapter_->PutValue(writer, i) == 0) {
                std::this_thread::yield();
            }
            // In SHARED mode, writer must consume its own data
            int wd = 0;
            adapter_->GetValue(writer, wd);
        }
    });

    producer.join();
    consumer.join();

    EXPECT_EQ(msg_count, consumed.load());

    close(epfd);
}

// --- Happy path: Producer full buffer fallback to epoll, get triggers wakeup ---
TEST_P(EpollTest, PutWakeupOnGet)
{
    // Small buffer so it fills quickly
    ASSERT_EQ(0, adapter_->Create(128, UFIFO_LOCK_THREAD, 2));

    ufifo_t *writer = adapter_->GetMainHandle();
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, adapter_->Attach(&reader));

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    int writer_fd = ufifo_get_tx_fd(writer);
    ASSERT_GE(writer_fd, 0);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = writer_fd;
    ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, writer_fd, &ev));

    // Fill the buffer until put fails.
    // In SHARED mode, writer must also consume its own data to advance its `out` pointer,
    // otherwise the writer itself becomes the slowest consumer and prematurely blocks.
    int put_count = 0;
    while (adapter_->PutValue(writer, put_count) > 0) {
        int wd = 0;
        adapter_->GetValue(writer, wd);
        put_count++;
    }
    EXPECT_GT(put_count, 0) << "Buffer should have absorbed some items before filling";

    // Now buffer is full because the reader hasn't consumed anything, so reader's out == 0.
    EXPECT_EQ(0, adapter_->PutValue(writer, 9999));

    // Drain all prior notifications from the initial put/get flurry on writer
    ufifo_drain_tx_fd(writer);

    // Verify epoll_wait blocks because there is no new activity
    struct epoll_event events[1];
    EXPECT_EQ(0, epoll_wait(epfd, events, 1, 50));

    // Reader consumes one item
    int out = 0;
    EXPECT_GT(adapter_->GetValue(reader, out), 0);
    EXPECT_EQ(0, out); // Should match the very first item (put_count started at 0)

    // The reader's get() should have triggered a notification to the writer
    int n = epoll_wait(epfd, events, 1, 1000);
    EXPECT_EQ(1, n);
    EXPECT_EQ(writer_fd, events[0].data.fd);

    ufifo_drain_tx_fd(writer);

    // With the reader having advanced min_out (its out pointer), the writer should now be able to put again
    EXPECT_GT(adapter_->PutValue(writer, 9999), 0);

    close(epfd);
}

// --- Regression: peek must NOT notify writers (it does not free capacity) ---
TEST_P(EpollTest, PeekDoesNotNotifyWriter)
{
    // Small buffer so it fills quickly
    ASSERT_EQ(0, adapter_->Create(128, UFIFO_LOCK_THREAD, 2));

    ufifo_t *writer = adapter_->GetMainHandle();
    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, adapter_->Attach(&reader));

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    int writer_fd = ufifo_get_tx_fd(writer);
    ASSERT_GE(writer_fd, 0);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = writer_fd;
    ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, writer_fd, &ev));

    // Fill the buffer until put fails (reader.out stays at 0).
    // In SHARED mode, the writer must also consume its own copy to keep
    // its own `out` pointer advancing.
    int put_count = 0;
    while (adapter_->PutValue(writer, put_count) > 0) {
        int wd = 0;
        adapter_->GetValue(writer, wd);
        put_count++;
    }
    EXPECT_GT(put_count, 0) << "Buffer should have absorbed some items before filling";
    EXPECT_EQ(0, adapter_->PutValue(writer, 9999));

    // Drain all prior notifications from the initial put/get flurry on writer
    ufifo_drain_tx_fd(writer);

    // Verify epoll_wait blocks because there is no new activity
    struct epoll_event events[1];
    EXPECT_EQ(0, epoll_wait(epfd, events, 1, 50));

    // Reader peeks — data is available, but nothing is consumed
    char buf[64];
    unsigned int peeked = 0;
    switch (GetParam()) {
    case DataFormat::BYTESTREAM:
        peeked = ufifo_peek(reader, buf, sizeof(int));
        break;
    case DataFormat::RECORD:
        peeked = ufifo_peek(reader, buf, sizeof(TestRecord) + sizeof(int));
        break;
    case DataFormat::TAG:
        peeked = ufifo_peek(reader, buf, sizeof(TaggedRecord) + sizeof(int));
        break;
    }
    EXPECT_GT(peeked, 0u) << "Peek should see data without consuming";

    // Peek must not signal the writer: available capacity is unchanged
    EXPECT_EQ(0, epoll_wait(epfd, events, 1, 100)) << "peek must not wake the writer";

    close(epfd);
}

// --- Failure path: spurious wakeup — epoll fires but FIFO has no data ---
TEST_P(EpollTest, SpuriousWakeupSafe)
{
    ASSERT_EQ(0, adapter_->Create(1024, UFIFO_LOCK_THREAD, 2));

    ufifo_t *reader = nullptr;
    ASSERT_EQ(0, adapter_->Attach(&reader));

    int epfd = epoll_create1(0);
    ASSERT_GE(epfd, 0);

    int fd = ufifo_get_rx_fd(reader);
    ASSERT_GE(fd, 0);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    ASSERT_EQ(0, epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev));

    // Put then immediately get on writer side — reader has nothing
    ufifo_t *writer = adapter_->GetMainHandle();
    EXPECT_GT(adapter_->PutValue(writer, 77), 0);
    int wd = 0;
    adapter_->GetValue(writer, wd); // writer consumes

    // epoll may fire (notification was sent), but ufifo_get should return 0
    struct epoll_event events[1];
    int n = epoll_wait(epfd, events, 1, 200);
    if (n > 0) {
        ufifo_drain_rx_fd(reader);
        int out = 0;
        // Reader should also see the data (SHARED mode — independent out pointers)
        // This is actually valid data for the reader, so consume it
        adapter_->GetValue(reader, out);
    }
    // The key assertion: no crash, no hang, no UB regardless of epoll result

    close(epfd);
}

INSTANTIATE_TEST_SUITE_P(EpollTests,
                         EpollTest,
                         testing::Values(DataFormat::BYTESTREAM, DataFormat::RECORD, DataFormat::TAG),
                         PrintDataFormat);

// =============================================================================
// 11. Crash Recovery & Dead Process Reaping Tests
// =============================================================================
