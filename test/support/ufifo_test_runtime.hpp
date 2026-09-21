#ifndef UFIFO_TEST_RUNTIME_HPP
#define UFIFO_TEST_RUNTIME_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <sys/types.h>

constexpr std::chrono::seconds TEST_PROCESS_TIMEOUT{ 5 };

class TestDeadline {
  public:
    explicit TestDeadline(std::chrono::milliseconds timeout);

    bool Expired() const;
    int RemainingMilliseconds() const;
    std::chrono::steady_clock::time_point TimePoint() const;

  private:
    std::chrono::steady_clock::time_point time_point_;
};

class FirstFailure {
  public:
    void Record(int failure);
    int Get() const;
    bool Ok() const;

  private:
    std::atomic<int> failure_{ 0 };
};

class StartGate {
  public:
    explicit StartGate(size_t participant_count);

    bool ArriveAndWait(const TestDeadline &deadline);
    bool Release(const TestDeadline &deadline);

  private:
    void CancelLocked();

    const size_t participant_count_;
    size_t ready_count_ = 0;
    bool started_ = false;
    bool cancelled_ = false;
    std::mutex mutex_;
    std::condition_variable ready_;
    std::condition_variable start_;
};

class TestPipe {
  public:
    TestPipe() = default;
    ~TestPipe();
    TestPipe(const TestPipe &) = delete;
    TestPipe &operator=(const TestPipe &) = delete;
    TestPipe(TestPipe &&other) noexcept;
    TestPipe &operator=(TestPipe &&other) noexcept;

    static int Create(TestPipe *output);
    int ReadByteUntil(const TestDeadline &deadline, char *value) const;
    int WriteByte(char value) const;
    void CloseRead();
    void CloseWrite();

  private:
    TestPipe(int read_fd, int write_fd);
    void CloseAll();

    int read_fd_ = -1;
    int write_fd_ = -1;
};

class ChildProcess {
  public:
    explicit ChildProcess(pid_t pid = -1);
    ~ChildProcess();
    ChildProcess(const ChildProcess &) = delete;
    ChildProcess &operator=(const ChildProcess &) = delete;
    ChildProcess(ChildProcess &&other) noexcept;
    ChildProcess &operator=(ChildProcess &&other) noexcept;

    int WaitUntil(const TestDeadline &deadline, int *status);
    bool Valid() const;

  private:
    void TerminateAndWait();

    pid_t pid_ = -1;
};

#endif /* UFIFO_TEST_RUNTIME_HPP */
