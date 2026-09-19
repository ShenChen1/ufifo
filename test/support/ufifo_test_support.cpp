#include "ufifo_test_support.hpp"

std::string GenerateName(const char *prefix)
{
    static std::atomic<int> counter{ 0 };
    return std::string(prefix) + "_" + std::to_string(counter++) + "_" + std::to_string(getpid());
}

const TestParam ALL_COMBINATIONS[] = { { DataFormat::BYTESTREAM, DataMode::SOLE, UFIFO_LOCK_NONE },
                                       { DataFormat::RECORD, DataMode::SOLE, UFIFO_LOCK_NONE },
                                       { DataFormat::TAG, DataMode::SOLE, UFIFO_LOCK_NONE },
                                       { DataFormat::BYTESTREAM, DataMode::SHARED, UFIFO_LOCK_NONE },
                                       { DataFormat::RECORD, DataMode::SHARED, UFIFO_LOCK_NONE },
                                       { DataFormat::TAG, DataMode::SHARED, UFIFO_LOCK_NONE },

                                       { DataFormat::BYTESTREAM, DataMode::SOLE, UFIFO_LOCK_THREAD },
                                       { DataFormat::RECORD, DataMode::SOLE, UFIFO_LOCK_THREAD },
                                       { DataFormat::TAG, DataMode::SOLE, UFIFO_LOCK_THREAD },
                                       { DataFormat::BYTESTREAM, DataMode::SHARED, UFIFO_LOCK_THREAD },
                                       { DataFormat::RECORD, DataMode::SHARED, UFIFO_LOCK_THREAD },
                                       { DataFormat::TAG, DataMode::SHARED, UFIFO_LOCK_THREAD },

                                       { DataFormat::BYTESTREAM, DataMode::SOLE, UFIFO_LOCK_PROCESS },
                                       { DataFormat::RECORD, DataMode::SOLE, UFIFO_LOCK_PROCESS },
                                       { DataFormat::TAG, DataMode::SOLE, UFIFO_LOCK_PROCESS },
                                       { DataFormat::BYTESTREAM, DataMode::SHARED, UFIFO_LOCK_PROCESS },
                                       { DataFormat::RECORD, DataMode::SHARED, UFIFO_LOCK_PROCESS },
                                       { DataFormat::TAG, DataMode::SHARED, UFIFO_LOCK_PROCESS } };

const size_t ALL_COMBINATIONS_COUNT = sizeof(ALL_COMBINATIONS) / sizeof(ALL_COMBINATIONS[0]);

std::string PrintParam(const testing::TestParamInfo<TestParam> &info)
{
    static const std::map<DataFormat, std::string> format_map = { { DataFormat::BYTESTREAM, "Byte" },
                                                                  { DataFormat::RECORD, "Record" },
                                                                  { DataFormat::TAG, "Tag" } };
    static const std::map<DataMode, std::string> mode_map = { { DataMode::SOLE, "Sole" },
                                                              { DataMode::SHARED, "Shared" } };
    static const std::map<ufifo_lock_e, std::string> lock_map = { { UFIFO_LOCK_NONE, "NoLock" },
                                                                  { UFIFO_LOCK_THREAD, "ThreadLock" },
                                                                  { UFIFO_LOCK_PROCESS, "ProcessLock" } };

    const std::string format = format_map.count(info.param.format) ? format_map.at(info.param.format) : "Unknown";
    const std::string mode = mode_map.count(info.param.mode) ? mode_map.at(info.param.mode) : "Unknown";
    const std::string lock = lock_map.count(info.param.lock) ? lock_map.at(info.param.lock) : "Unknown";
    return format + "_" + mode + "_" + lock;
}
