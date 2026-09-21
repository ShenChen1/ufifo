#include "ufifo_test_support.hpp"

class TagSpecificTest : public ::testing::Test {
  protected:
    ufifo_t *fifo_ = nullptr;
    std::string name_;

    void SetUp() override
    {
        name_ = GenerateName("tag_spec");
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = 2048;
        init.alloc.force = 1;
        init.alloc.data_mode = UFIFO_DATA_SOLE;
        init.alloc.lock = UFIFO_LOCK_NONE;
        init.alloc.max_users = 1;
        init.hook.recsize = tagged_recsize;
        init.hook.rectag = tagged_rectag;

        ASSERT_EQ(0, ufifo_open(name_.c_str(), &init, &fifo_));
        ASSERT_NE(nullptr, fifo_);
    }

    void TearDown() override
    {
        if (fifo_)
            ufifo_destroy(fifo_);
    }

    void PutRec(int tag, const std::string &data)
    {
        alignas(TaggedRecord) char buf[256];
        ASSERT_LE(data.size() + 1, sizeof(buf) - sizeof(TaggedRecord));
        TaggedRecord *rec = reinterpret_cast<TaggedRecord *>(buf);
        rec->size = data.size() + 1;
        rec->tag = tag;
        memcpy(rec->data, data.c_str(), rec->size);
        const size_t record_size = sizeof(TaggedRecord) + rec->size;
        ASSERT_EQ(static_cast<ssize_t>(record_size), ufifo_put(fifo_, rec, record_size));
    }
};

TEST_F(TagSpecificTest, OldestByTag)
{
    PutRec(1, "first_1");
    PutRec(2, "first_2");
    PutRec(1, "second_1");
    PutRec(2, "second_2");

    ASSERT_EQ(0, ufifo_oldest(fifo_, 2));
    alignas(TaggedRecord) char out_buf[128] = {};
    TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(TaggedRecord) + strlen("first_2") + 1),
              ufifo_get(fifo_, out, sizeof(out_buf)));
    EXPECT_EQ(2u, out->tag);
    EXPECT_STREQ("first_2", out->data);
}

TEST_F(TagSpecificTest, NewestByTag)
{
    PutRec(1, "first_1");
    PutRec(2, "first_2");
    PutRec(1, "second_1");

    ASSERT_EQ(0, ufifo_newest(fifo_, 1));
    alignas(TaggedRecord) char out_buf[128] = {};
    TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(TaggedRecord) + strlen("second_1") + 1),
              ufifo_get(fifo_, out, sizeof(out_buf)));
    EXPECT_EQ(1u, out->tag);
    EXPECT_STREQ("second_1", out->data);
}

TEST_F(TagSpecificTest, TagNotFound)
{
    PutRec(1, "data");
    errno = 0;
    EXPECT_EQ(-ESPIPE, ufifo_oldest(fifo_, 999));
    EXPECT_EQ(ESPIPE, errno);
    EXPECT_EQ(0, ufifo_len(fifo_));
    alignas(TaggedRecord) char out_buf[128] = {};
    errno = 0;
    EXPECT_EQ(-EAGAIN, ufifo_get(fifo_, out_buf, sizeof(out_buf)));
    EXPECT_EQ(EAGAIN, errno);
}

TEST_F(TagSpecificTest, MultiTagMixed)
{
    for (int i = 0; i < 10; i++) {
        char content[16];
        snprintf(content, sizeof(content), "tag%d_%d", i % 3, i);
        PutRec(i % 3, content);
    }

    int count = 0;
    while (ufifo_len(fifo_) > 0) {
        ASSERT_EQ(0, ufifo_oldest(fifo_, 0));
        alignas(TaggedRecord) char out_buf[128] = {};
        TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
        ASSERT_GT(ufifo_get(fifo_, out, sizeof(out_buf)), 0);
        ASSERT_EQ(0u, out->tag);
        count++;
    }
    EXPECT_EQ(4, count);
}
