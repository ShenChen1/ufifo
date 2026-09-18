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

        ufifo_open(name_.c_str(), &init, &fifo_);
    }

    void TearDown() override
    {
        if (fifo_)
            ufifo_destroy(fifo_);
    }

    void PutRec(int tag, const std::string &data)
    {
        char buf[256];
        TaggedRecord *rec = reinterpret_cast<TaggedRecord *>(buf);
        rec->size = data.size() + 1;
        rec->tag = tag;
        memcpy(rec->data, data.c_str(), rec->size);
        ufifo_put(fifo_, rec, sizeof(TaggedRecord) + rec->size);
    }
};

TEST_F(TagSpecificTest, OldestByTag)
{
    PutRec(1, "first_1");
    PutRec(2, "first_2");
    PutRec(1, "second_1");
    PutRec(2, "second_2");

    ufifo_oldest(fifo_, 2); // seek to oldest with tag=2
    char out_buf[128] = {};
    TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
    ufifo_get(fifo_, out, sizeof(out_buf));
    EXPECT_EQ(2u, out->tag);
    EXPECT_EQ(0, memcmp(out->data, "first_2", 7));
}

TEST_F(TagSpecificTest, NewestByTag)
{
    PutRec(1, "first_1");
    PutRec(2, "first_2");
    PutRec(1, "second_1");

    ufifo_newest(fifo_, 1); // seek to newest with tag=1
    char out_buf[128] = {};
    TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
    ufifo_get(fifo_, out, sizeof(out_buf));
    EXPECT_EQ(1u, out->tag);
    EXPECT_EQ(0, memcmp(out->data, "second_1", 8));
}

TEST_F(TagSpecificTest, TagNotFound)
{
    PutRec(1, "data");
    ufifo_oldest(fifo_, 999); // non-existent tag
    char out_buf[128] = {};
    ssize_t ret = ufifo_get(fifo_, out_buf, sizeof(out_buf));
    (void)ret; // shouldn't crash
}

TEST_F(TagSpecificTest, MultiTagMixed)
{
    for (int i = 0; i < 10; i++) {
        char content[16];
        snprintf(content, sizeof(content), "tag%d_%d", i % 3, i);
        PutRec(i % 3, content);
    }

    int count = 0;
    while (ufifo_len(fifo_)) {
        ufifo_oldest(fifo_, 0);
        char out_buf[128] = {};
        TaggedRecord *out = reinterpret_cast<TaggedRecord *>(out_buf);
        if (ufifo_get(fifo_, out, sizeof(out_buf)) == 0)
            break;
        if (out->tag == 0)
            count++;
        else
            break;
    }
    EXPECT_GT(count, 0);
}

// =============================================================================
// 9. Edge Cases
// =============================================================================
