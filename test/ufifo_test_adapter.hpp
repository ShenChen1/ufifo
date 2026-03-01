#pragma once

#include <cstddef>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <vector>

extern "C" {
#include "ufifo.h"
}

enum class DataFormat { BYTESTREAM, RECORD, TAG };
enum class DataMode { SOLE, SHARED };

struct TestParam {
    DataFormat format;
    DataMode mode;
};

// Record structure for Record/Tag mode tests
struct TestRecord {
    unsigned int size;
    char data[0];
};

struct TaggedRecord {
    unsigned int size;
    unsigned int tag;
    char data[0];
};

// Hooks
unsigned int test_recsize(unsigned char *p1, unsigned int n1, unsigned char *p2)
{
    unsigned int size = sizeof(TestRecord);
    if (n1 >= size) {
        TestRecord *rec = reinterpret_cast<TestRecord *>(p1);
        size = rec->size;
    } else {
        TestRecord rec;
        char *p = reinterpret_cast<char *>(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        size = rec.size;
    }
    return sizeof(TestRecord) + size;
}

unsigned int tagged_recsize(unsigned char *p1, unsigned int n1, unsigned char *p2)
{
    unsigned int size = sizeof(TaggedRecord);
    if (n1 >= size) {
        TaggedRecord *rec = reinterpret_cast<TaggedRecord *>(p1);
        size = rec->size;
    } else {
        TaggedRecord rec;
        char *p = reinterpret_cast<char *>(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        size = rec.size;
    }
    return sizeof(TaggedRecord) + size;
}

unsigned int tagged_rectag(unsigned char *p1, unsigned int n1, unsigned char *p2)
{
    unsigned int tag = 0;
    unsigned int size = sizeof(TaggedRecord);
    if (n1 >= size) {
        TaggedRecord *rec = reinterpret_cast<TaggedRecord *>(p1);
        tag = rec->tag;
    } else {
        TaggedRecord rec;
        char *p = reinterpret_cast<char *>(&rec);
        memcpy(p, p1, n1);
        memcpy(p + n1, p2, size - n1);
        tag = rec.tag;
    }
    return tag;
}

class UfifoTestAdapter {
  public:
    UfifoTestAdapter(DataFormat format, DataMode mode, const std::string &name)
        : format_(format), mode_(mode), name_(name)
    {}

    virtual ~UfifoTestAdapter()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t i = handles_.size(); i > 0; --i) {
            if (handles_[i - 1]) {
                if (i - 1 == 0) {
                    ufifo_destroy(handles_[i - 1]);
                } else {
                    ufifo_close(handles_[i - 1]);
                }
            }
        }
        handles_.clear();
    }

    int Create(unsigned int size, ufifo_lock_e lock = UFIFO_LOCK_NONE, unsigned int max_users = 10)
    {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ALLOC;
        init.alloc.size = size;
        init.alloc.force = 1;
        init.alloc.lock = lock;
        init.alloc.data_mode = (mode_ == DataMode::SHARED) ? UFIFO_DATA_SHARED : UFIFO_DATA_SOLE;
        init.alloc.max_users = max_users;

        switch (format_) {
        case DataFormat::RECORD:
            init.hook.recsize = test_recsize;
            break;
        case DataFormat::TAG:
            init.hook.recsize = tagged_recsize;
            init.hook.rectag = tagged_rectag;
            break;
        default:
            break;
        }

        ufifo_t *fifo = nullptr;
        int ret = ufifo_open(const_cast<char *>(name_.c_str()), &init, &fifo);
        if (ret == 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            handles_.push_back(fifo);
        }
        return ret;
    }

    int Detach(ufifo_t *handle)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (size_t i = 0; i < handles_.size(); i++) {
                if (handles_[i] == handle) {
                    handles_[i] = nullptr;
                    break;
                }
            }
        }

        return ufifo_close(handle);
    }

    int Attach(ufifo_t **handle)
    {
        ufifo_init_t init = {};
        init.opt = UFIFO_OPT_ATTACH;

        switch (format_) {
        case DataFormat::RECORD:
            init.hook.recsize = test_recsize;
            break;
        case DataFormat::TAG:
            init.hook.recsize = tagged_recsize;
            init.hook.rectag = tagged_rectag;
            break;
        default:
            break;
        }

        int ret = ufifo_open(const_cast<char *>(name_.c_str()), &init, handle);
        if (ret == 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            handles_.push_back(*handle);
        }
        return ret;
    }

    // Unifies putting an integer value with a payload. (Tag uses modulo of value for tag if TAG format)
    int PutValue(ufifo_t *handle, int value, int tag = -1, long timeout_ms = 0)
    {
        char buf[64];
        size_t size = sizeof(buf);

        if (format_ == DataFormat::BYTESTREAM) {
            memcpy(buf, &value, sizeof(value));
            size = sizeof(value);
        } else if (format_ == DataFormat::RECORD) {
            TestRecord *rec = reinterpret_cast<TestRecord *>(buf);
            rec->size = sizeof(int);
            memcpy(rec->data, &value, sizeof(value));
            size = sizeof(TestRecord) + rec->size;
        } else { // TAG
            TaggedRecord *rec = reinterpret_cast<TaggedRecord *>(buf);
            rec->size = sizeof(int);
            rec->tag = (tag >= 0) ? tag : (value % 5);
            memcpy(rec->data, &value, sizeof(value));
            size = sizeof(TaggedRecord) + rec->size;
        }

        if (timeout_ms > 0) {
            return ufifo_put_timeout(handle, buf, size, timeout_ms);
        } else if (timeout_ms == 0) {
            return ufifo_put(handle, buf, size);
        } else {
            return ufifo_put_block(handle, buf, size);
        }
    }

    int GetValue(ufifo_t *handle, int &value, long timeout_ms = 0)
    {
        char buf[64] = {};
        size_t size = sizeof(buf);
        unsigned int ret = 0;
        if (format_ == DataFormat::BYTESTREAM) {
            size = sizeof(value);
        } else if (format_ == DataFormat::RECORD) {
            size = sizeof(value) + sizeof(TestRecord);
        } else { // TAG
            size = sizeof(value) + sizeof(TaggedRecord);
        }

        if (timeout_ms > 0) {
            ret = ufifo_get_timeout(handle, buf, size, timeout_ms);
        } else if (timeout_ms == 0) {
            ret = ufifo_get(handle, buf, size);
        } else {
            ret = ufifo_get_block(handle, buf, size);
        }
        if (ret == 0)
            return 0;

        if (format_ == DataFormat::RECORD) {
            TestRecord *out = reinterpret_cast<TestRecord *>(buf);
            memcpy(&value, out->data, sizeof(value));
        } else if (format_ == DataFormat::TAG) {
            TaggedRecord *out = reinterpret_cast<TaggedRecord *>(buf);
            memcpy(&value, out->data, sizeof(value));
        } else {
            memcpy(&value, buf, sizeof(value));
        }

        return ret;
    }

    int PeekLen(ufifo_t *handle)
    {
        return ufifo_peek_len(handle);
    }

    int Skip(ufifo_t *handle)
    {
        size_t size = format_ == DataFormat::BYTESTREAM ? sizeof(int) : 1;
        for (size_t i = 0; i < size; i++) {
            ufifo_skip(handle);
        }
        return 0;
    }

    ufifo_t *GetMainHandle() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return handles_.empty() ? nullptr : handles_[0];
    }

    ufifo_t *GetHandle(size_t user_id = 1) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return (handles_.size() > user_id) ? handles_[user_id] : (handles_.empty() ? nullptr : handles_[0]);
    }

    DataMode GetMode() const
    {
        return mode_;
    }
    DataFormat GetFormat() const
    {
        return format_;
    }

  protected:
    DataFormat format_;
    DataMode mode_;
    std::string name_;
    std::vector<ufifo_t *> handles_;
    mutable std::mutex mutex_;
};
