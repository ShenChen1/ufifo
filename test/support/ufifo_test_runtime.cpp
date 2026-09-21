#include "ufifo_test_runtime.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <csignal>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>

TestDeadline::TestDeadline(std::chrono::milliseconds timeout)
    : time_point_(std::chrono::steady_clock::now() + std::max(timeout, std::chrono::milliseconds::zero()))
{}

bool TestDeadline::Expired() const
{
    return std::chrono::steady_clock::now() >= time_point_;
}

int TestDeadline::RemainingMilliseconds() const
{
    const auto remaining = time_point_ - std::chrono::steady_clock::now();
    if (remaining <= std::chrono::steady_clock::duration::zero())
        return 0;

    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    if (milliseconds < remaining)
        milliseconds++;
    return static_cast<int>(std::min<int64_t>(milliseconds.count(), INT_MAX));
}

std::chrono::steady_clock::time_point TestDeadline::TimePoint() const
{
    return time_point_;
}

void FirstFailure::Record(int failure)
{
    if (failure == 0)
        return;
    int no_failure = 0;
    failure_.compare_exchange_strong(no_failure, failure);
}

int FirstFailure::Get() const
{
    return failure_.load();
}

bool FirstFailure::Ok() const
{
    return Get() == 0;
}

StartGate::StartGate(size_t participant_count) : participant_count_(participant_count) {}

bool StartGate::ArriveAndWait(const TestDeadline &deadline)
{
    std::unique_lock<std::mutex> lock(mutex_);
    ready_count_++;
    ready_.notify_one();
    if (!start_.wait_until(lock, deadline.TimePoint(), [&] { return started_ || cancelled_; })) {
        CancelLocked();
        return false;
    }
    return started_;
}

bool StartGate::Release(const TestDeadline &deadline)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (!ready_.wait_until(lock, deadline.TimePoint(), [&] { return ready_count_ == participant_count_; })) {
        CancelLocked();
        return false;
    }
    started_ = true;
    lock.unlock();
    start_.notify_all();
    return true;
}

void StartGate::CancelLocked()
{
    cancelled_ = true;
    ready_.notify_all();
    start_.notify_all();
}

TestPipe::TestPipe(int read_fd, int write_fd) : read_fd_(read_fd), write_fd_(write_fd) {}

TestPipe::~TestPipe()
{
    CloseAll();
}

TestPipe::TestPipe(TestPipe &&other) noexcept : read_fd_(other.read_fd_), write_fd_(other.write_fd_)
{
    other.read_fd_ = -1;
    other.write_fd_ = -1;
}

TestPipe &TestPipe::operator=(TestPipe &&other) noexcept
{
    if (this == &other)
        return *this;
    CloseAll();
    read_fd_ = other.read_fd_;
    write_fd_ = other.write_fd_;
    other.read_fd_ = -1;
    other.write_fd_ = -1;
    return *this;
}

int TestPipe::Create(TestPipe *output)
{
    if (output == nullptr)
        return -EINVAL;
    int descriptors[2] = {};
    if (pipe(descriptors) != 0)
        return -errno;
    *output = TestPipe(descriptors[0], descriptors[1]);
    return 0;
}

int TestPipe::ReadByteUntil(const TestDeadline &deadline, char *value) const
{
    if (read_fd_ < 0 || value == nullptr)
        return -EINVAL;
    for (;;) {
        pollfd descriptor = { read_fd_, POLLIN, 0 };
        const int result = poll(&descriptor, 1, deadline.RemainingMilliseconds());
        if (result == 0)
            return -ETIMEDOUT;
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        const ssize_t bytes_read = read(read_fd_, value, 1);
        if (bytes_read == 1)
            return 0;
        if (bytes_read == 0)
            return -EPIPE;
        if (errno != EINTR)
            return -errno;
    }
}

int TestPipe::WriteByte(char value) const
{
    if (write_fd_ < 0)
        return -EINVAL;
    for (;;) {
        const ssize_t bytes_written = write(write_fd_, &value, 1);
        if (bytes_written == 1)
            return 0;
        if (bytes_written == 0)
            return -EIO;
        if (errno != EINTR)
            return -errno;
    }
}

void TestPipe::CloseRead()
{
    if (read_fd_ >= 0)
        close(read_fd_);
    read_fd_ = -1;
}

void TestPipe::CloseWrite()
{
    if (write_fd_ >= 0)
        close(write_fd_);
    write_fd_ = -1;
}

void TestPipe::CloseAll()
{
    CloseRead();
    CloseWrite();
}

ChildProcess::ChildProcess(pid_t pid) : pid_(pid) {}

ChildProcess::~ChildProcess()
{
    TerminateAndWait();
}

ChildProcess::ChildProcess(ChildProcess &&other) noexcept : pid_(other.pid_)
{
    other.pid_ = -1;
}

ChildProcess &ChildProcess::operator=(ChildProcess &&other) noexcept
{
    if (this == &other)
        return *this;
    TerminateAndWait();
    pid_ = other.pid_;
    other.pid_ = -1;
    return *this;
}

int ChildProcess::WaitUntil(const TestDeadline &deadline, int *status)
{
    if (pid_ <= 0 || status == nullptr)
        return -EINVAL;
    for (;;) {
        const pid_t result = waitpid(pid_, status, WNOHANG);
        if (result == pid_) {
            pid_ = -1;
            return 0;
        }
        if (result < 0 && errno != EINTR) {
            const int failure = -errno;
            pid_ = -1;
            return failure;
        }
        if (deadline.Expired()) {
            TerminateAndWait();
            return -ETIMEDOUT;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool ChildProcess::Valid() const
{
    return pid_ > 0;
}

void ChildProcess::TerminateAndWait()
{
    if (pid_ <= 0)
        return;
    if (kill(pid_, SIGKILL) != 0 && errno != ESRCH) {
        pid_ = -1;
        return;
    }
    while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {
    }
    pid_ = -1;
}
