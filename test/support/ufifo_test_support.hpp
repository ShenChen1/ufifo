#ifndef UFIFO_TEST_SUPPORT_HPP
#define UFIFO_TEST_SUPPORT_HPP

#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstring>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "ufifo_test_adapter.hpp"
#include "ufifo_test_runtime.hpp"

extern "C" {
#include "ufifo_internal.h"
#include "ufifo_layout.h"
}

std::string GenerateName(const char *prefix);
std::string PrintParam(const testing::TestParamInfo<TestParam> &info);
bool WaitForWaitWordArm(const ufifo_atomic_uint32_t *wait_word,
                        std::chrono::milliseconds timeout = std::chrono::seconds(1));

extern const TestParam ALL_COMBINATIONS[18];
extern const size_t ALL_COMBINATIONS_COUNT;

class EdgeCaseTest : public ::testing::Test {};

#endif /* UFIFO_TEST_SUPPORT_HPP */
