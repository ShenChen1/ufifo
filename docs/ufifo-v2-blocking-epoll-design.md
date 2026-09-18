# ufifo v2 Blocking 与 Epoll 重构设计

- 状态：Proposed
- 日期：2026-09-17
- 决策范围：blocking API、epoll adapter、通知状态与相关生命周期
- 目标版本：ufifo v2，Linux 6.7+

## 1. Problem 1-Pager

### Context

ufifo 当前以共享内存 ring buffer 传输数据，同时用同一组 `eventfd` 支撑 blocking API 和 epoll API。匿名 `eventfd` 需要由独立 broker 进程长期持有，并通过 UDS/`SCM_RIGHTS` 分发给后续 attach 的进程。

当前实现涉及以下耦合：

- `ufifo_open()` 无条件获取 eventfd 并可能创建 broker；
- blocking API 通过 `poll(eventfd)` 睡眠；
- epoll API 直接暴露每个 FIFO 的 RX/TX eventfd；
- 共享控制区保存 waiter、armed 和 broker generation；
- close/destroy、broker 退出、进程崩溃和 fd 继承共同决定资源生命周期。

### Problem

现有方案把 FIFO 数据生命周期扩展成了“共享内存 + broker 进程 + UDS 协议 + 一组匿名 fd”的组合生命周期。blocking waiter 和 epoll listener 又共享通知计数，导致正确性、恢复逻辑和性能优化相互牵制。

需要在不引入 fallback 和 liburing 依赖的前提下，同时满足：

- 跨进程 blocking read/write 不丢唤醒；
- 多个 FIFO 能加入应用现有 epoll event loop；
- io_uring 对应用完全不可见；
- 无等待者时数据热路径不执行通知 syscall；
- broker、UDS 和 eventfd 通知路径全部删除。

### Goal

1. core 只拥有共享 FIFO 状态、readiness predicate 和可等待状态字。
2. blocking API 使用共享 futex，保留现有非阻塞、无限等待和严格超时语义。
3. epoll adapter 在进程内拥有一个 raw io_uring，并聚合监听多个 `ufifo_t`。
4. adapter 只暴露一个可加入系统 epoll 的 fd，以及 ADD/MOD/DEL/drain API。
5. 所有等待、取消、close 和进程崩溃路径都具备明确所有权。
6. 最终源码只保留一套通知实现，不保留 v1 compatibility path。

### Non-Goals

- 不支持 Linux 6.7 以前的内核。
- 不提供 eventfd、UDS、broker 或 liburing fallback。
- 不把 io_uring SQE/CQE、ring 或 futex 地址暴露给应用。
- 不提供严格 level-triggered adapter 语义。
- 不保证 fork 后继续使用继承的 adapter。
- 本次不改变 SOLE/SHARED、byte-stream/record/tag 的数据分发语义。
- 不提供旧双-shm 布局的 attach、force 迁移或 broker 清理路径。

### Constraints

- C99；Linux 专用；最低运行内核 6.7。
- 构建环境必须提供含 `IORING_OP_FUTEX_WAIT` 和 `FUTEX2_SIZE_U32` 的 Linux UAPI headers。
- 不新增运行时第三方依赖。
- 公共函数参数不超过 5 个；单函数不超过 80 行；单源码文件不超过 500 行。
- 控制接口沿用“成功返回非负值、失败返回负 errno”；数据接口继续用 `0 + errno`。
- 所有共享 futex 必须使用 shared futex 语义，禁止 `FUTEX_PRIVATE`/`FUTEX2_PRIVATE`。

## 2. 已确认的假设

1. 可以做 v2 ABI break，并直接删除旧 API 与旧共享内存布局。
2. 不保留 `ufifo_get_rx_fd()`、`ufifo_get_tx_fd()`、`ufifo_drain_*_fd()`。
3. `ufifo_epoll_ctl()` 可以由多个线程调用；`ufifo_epoll_drain()` 只有一个消费者。
4. `ufifo_epoll_close()` 以及 `ufifo_close()`/`ufifo_destroy()` 由调用方保证不与其他相关调用并发。
5. `UFIFO_EPOLLOUT` 使用每个 watch 独立的 `write_threshold`。
6. fork 后子进程不能继续 ctl/drain；只能本地释放继承的 adapter，然后重新创建。

## 3. 现状审计与影响

| 位置 | 当前职责 | v2 影响 |
| --- | --- | --- |
| `inc/ufifo_layout.h` | waiter、epoll armed、broker generation | ABI 重做为 RX/TX wait word |
| `inc/ufifo_internal.h` | eventfd/broker 字段和通知 helper | 删除；加入 futex wait/notify 与本地 watch ref |
| `src/ufifo_sync.c` | mutex、OFD lock、eventfd poll/wake | 保留锁与 OFD；eventfd 部分替换为 futex primitive |
| `src/ufifo_opts.c` | predicate、blocking loop、数据路径通知 | 拆分文件；改用 wait word |
| `src/ufifo_epoll.c` | 每 handle 暴露 RX/TX eventfd | 重写为 adapter/watch 层 |
| `src/ufifo_broker*.c` | eventfd 创建、分发与 daemon 生命周期 | 删除 |
| `src/ufifo_init.c` | open 时获取 eventfd，close 时关闭 broker 资源 | core open/close 不再创建通知 fd |
| `README.md`、`example/epoll.c` | 说明和演示旧 eventfd API | 改为 adapter API |
| `test/ufifo_test.cpp` | eventfd、broker、blocking 与 epoll 测试混合 | 按领域拆分并替换旧测试 |

现有 `src/ufifo_opts.c`、`test/ufifo_test.cpp` 和 `test/ufifo_bench.cpp` 已超过新规则的 500 行限制。实现阶段在触碰这些文件前必须先按职责拆分，不能继续扩张。

## 4. 方案比较

### 4.1 总体通知架构

| 方案 | 优点 | 缺点/风险 | 结论 |
| --- | --- | --- | --- |
| futex + eventfd broker | eventfd 原生可 epoll；单次通知短 | broker/UDS/fd 分发生命周期复杂 | 拒绝 |
| futex + UDS | 命名和重连直接 | socket、skb、队列和 syscall 路径更重 | 拒绝 |
| futex + 对外 io_uring API | 无 broker；异步能力直接 | 泄露实现，强迫应用拥有 ring | 拒绝 |
| futex + 私有 io_uring epoll adapter | 无 broker；一个 ring 聚合多个 FIFO；API 稳定 | 需要维护小型 raw ring engine | 采用 |

### 4.2 共享等待状态

| 方案 | 优点 | 缺点/风险 | 结论 |
| --- | --- | --- | --- |
| 每次状态变化无条件 `seq++` | 最容易证明正确 | 无监听时仍产生跨核 atomic RMW | 拒绝 |
| `seq + waiter count` | 可跳过无用 wake | 进程崩溃可能永久泄漏计数 | 拒绝 |
| 单个 `epoch + armed` 32 位字 | 无 waiter 时只读；崩溃只导致一次额外 wake；天然合并 | wake 时采用广播，可能有惊群 | 采用 |

### 4.3 Adapter 触发语义

| 方案 | 优点 | 缺点/风险 | 结论 |
| --- | --- | --- | --- |
| Level-triggered | 使用直观 | 需要额外 fd/状态维持持续 readable | 拒绝 |
| Edge-triggered | 与 one-shot futex wait 匹配；可自然合并 burst | 应用必须 drain FIFO 到 `EAGAIN` | 采用 |

## 5. 最终架构与所有权

```text
Application
  epoll_wait(system_epfd)
          |
          | EPOLLIN on ufifo_epoll_fd()
          v
ufifo epoll adapter (process-local)
  - one raw io_uring
  - watch table + ready queue
  - ADD / MOD / DEL / drain
          |
          | IORING_OP_FUTEX_WAIT
          v
ufifo core (shared memory)
  - in/out/cached_min_out
  - RX/TX readiness predicates
  - rx_wait_word / tx_wait_word
          |
          | shared FUTEX_WAKE
          v
blocking waiters and adapter waits
```

### 5.1 Core

Core 拥有：

- FIFO 数据和索引；
- SOLE/SHARED 的 read/write predicate；
- 两个共享 32 位 wait word；
- futex arm、wait 和 notify primitive；
- handle 映射和本地 watch reference。

Core 不知道：

- io_uring ring、SQE、CQE；
- 系统 epoll；
- adapter watch table；
- 用户传入的 epoll data。

### 5.2 Epoll adapter

Adapter 是普通进程本地对象：

- 创建时拥有一个 ring fd 及其 SQ/CQ/SQE mappings；
- 最多注册 `capacity` 个 `ufifo_t`；
- 每个 watch 最多维护一个 RX wait 和一个 TX wait；
- 持有被监听 handle 的本地强引用；
- close 时同步取消全部 wait、释放引用、unmap 并关闭 ring fd。

### 5.3 Application

应用只知道：

- adapter fd 可按 `EPOLLIN` 加入现有 epoll；
- `ufifo_epoll_drain()` 把内部 completion 转换成 ufifo readiness event；
- 收到 IN 后读取到 `EAGAIN`；收到 OUT 后写入直到目标写入失败或不再满足阈值。

应用不得监听 adapter fd 的 `EPOLLOUT`。Linux 的 ring fd 在 SQ 未满时本身会报告 `EPOLLOUT`，它不代表任何 FIFO 可写。

## 6. Public API

新建独立公开头文件 `inc/ufifo_epoll.h`，并由安装规则与 `ufifo.h` 一起发布。

```c
typedef struct ufifo_epoll ufifo_epoll_t;

enum {
    UFIFO_EPOLLIN  = 1U << 0,
    UFIFO_EPOLLOUT = 1U << 1,
    UFIFO_EPOLLERR = 1U << 2,
};

enum {
    UFIFO_EPOLL_CTL_ADD = 1,
    UFIFO_EPOLL_CTL_MOD = 2,
    UFIFO_EPOLL_CTL_DEL = 3,
};

typedef union {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} ufifo_epoll_data_t;

typedef struct {
    uint32_t events;
    uint32_t reserved;
    size_t write_threshold;
    ufifo_epoll_data_t data;
} ufifo_epoll_event_t;

int ufifo_epoll_create(size_t capacity, ufifo_epoll_t **out);
int ufifo_epoll_fd(const ufifo_epoll_t *ep);
int ufifo_epoll_ctl(ufifo_epoll_t *ep, int op, ufifo_t *fifo,
                    const ufifo_epoll_event_t *event);
int ufifo_epoll_drain(ufifo_epoll_t *ep, ufifo_epoll_event_t *events,
                      size_t maxevents);
int ufifo_epoll_close(ufifo_epoll_t *ep);
```

### 6.1 返回值

- `create/ctl/close`：成功为 `0`，失败为负 errno。
- `fd`：成功为非负 fd，失败为负 errno。
- `drain`：成功为返回事件数量，失败为负 errno。
- 控制 API 不使用“`-1` 并设置 errno”的混合约定。

### 6.2 参数规则

- `capacity == 0`：`-EINVAL`。
- `events` 含未知位、`reserved != 0`：`-EINVAL`。
- ADD 已存在：`-EEXIST`；MOD/DEL 不存在：`-ENOENT`。
- DEL 允许 `event == NULL`；ADD/MOD 要求非空。
- 监听 OUT 时 `write_threshold` 必须在 `[1, ufifo_size(fifo)]`，否则 `-EMSGSIZE`。
- 不监听 OUT 时 `write_threshold` 必须为 `0`。

## 7. Readiness 契约

### 7.1 RX

```text
UFIFO_EPOLLIN := in != this_handle.out
```

SHARED 模式下 predicate 使用该 handle 独立的 `out`；SOLE 模式下使用全局消费位置。

### 7.2 TX

```text
UFIFO_EPOLLOUT := unused_bytes >= write_threshold
```

`write_threshold` 是传给 `ufifo_put*()` 的真实总字节数。record header、payload 和调用方自定义编码开销必须已经包含在该值中。

### 7.3 Edge-triggered 行为

- ADD/MOD 后 predicate 已成立时，必须生成一次初始 event。
- 一次 watch 在 ready queue 中最多出现一次；后续完成只 OR 到 `pending_mask`。
- completion 只表示“状态可能变化”，adapter 必须重新检查 predicate。
- predicate 不成立时允许无用户事件的 spurious adapter wake。
- 应用若未处理到 `EAGAIN`，后续不保证再次收到同一 readiness。

## 8. Shared wait word

控制区新增两个 4 字节对齐的原子字：

```c
uint32_t rx_wait_word;
uint32_t tx_wait_word;
```

最低位是 `ARMED`，高 31 位是 epoch：

```text
even value: ARMED=0
odd value:  ARMED=1
wake:       odd N -> even N+1
```

### 8.1 Arm

```text
expected = atomic_fetch_or(wait_word, ARMED) | ARMED
recheck readiness predicate
wait only while *wait_word == expected
```

设置 ARMED 必须发生在最后一次 predicate 检查之前。状态若在 arm 与内核入队之间变化，wait word 已改变，futex wait 会以 `EAGAIN` 完成，不会睡过通知。

### 8.2 Notify

数据/索引必须先以 release 语义发布，然后执行：

```text
old = atomic_load(wait_word)
while old has ARMED:
    if compare_exchange(old, old + 1):
        futex_wake_shared(wait_word, INT_MAX)
        break
```

性质：

- 没有 waiter 时只有 atomic load，不修改 cache line，不执行 syscall；
- 多个 waiter 共用一个 ARMED bit，成功的 waker 广播唤醒；
- waiter 超时或进程崩溃最多留下一个 ARMED bit；下一次状态变化会清除它；
- epoch 回绕只在 arm-to-wait 窗口内恰好发生 `2^31` 次通知时构成 ABA，作为不可实现的运行边界记录，不额外增加 64 位 ABI。

### 8.3 Blocking loop

blocking read/write 统一执行：

1. 在当前 data-lock 语义下检查 predicate；成立则直接操作。
2. arm 对应 wait word。
3. 再次检查 predicate；成立则重试数据操作。
4. 释放 data lock，执行 shared futex wait。
5. 重新获取 data lock并回到步骤 1。

无限等待使用 `FUTEX_WAIT`；超时使用 monotonic absolute deadline，spurious wake 不得重置 deadline。`EAGAIN` 视为状态变化并重试；`EINTR` 和 `ETIMEDOUT` 按现有 API 错误约定返回。

### 8.4 状态变化映射

- 成功 put：publish `in` 后 notify RX。
- 成功 get/skip/oldest/newest：publish `out` 后 notify TX。
- SHARED reader close/reap、reset、attach 导致可用容量增加：notify TX。
- 只读 peek 不 notify TX。

## 9. Raw io_uring engine

### 9.1 Setup

- 仅使用 `io_uring_setup`、`mmap`、`io_uring_enter`、`io_uring_register` syscall。
- 使用 `IORING_SETUP_CQSIZE`；不使用 SQPOLL、IOPOLL 或 `IORING_SETUP_SINGLE_ISSUER`。
- SQ entries：`next_pow2(max(8, 2 * capacity))`。
- CQ entries：`next_pow2(max(16, 4 * capacity))`。
- 要求 `IORING_FEAT_NODROP`，否则 `create` 返回 `-EOPNOTSUPP`。
- 用 `IORING_REGISTER_PROBE` 验证 `IORING_OP_FUTEX_WAIT`；不根据 `uname()` 猜能力。

### 9.2 Futex wait SQE

每个 wait 使用 Linux 6.7 UAPI 的以下字段：

```text
opcode       = IORING_OP_FUTEX_WAIT
fd           = FUTEX2_SIZE_U32
addr         = wait_word address
off/addr2    = expected value
len          = 0
futex_flags  = 0
addr3        = FUTEX_BITSET_MATCH_ANY
user_data    = packed watch token
```

`fd` 中不设置 `FUTEX2_PRIVATE`，因为 wait word 位于跨进程 `MAP_SHARED` 映射。

### 9.3 Token

`user_data` 只编码 slot index、32 位 generation 和 operation kind，不存裸指针。operation kind 至少包含 RX_WAIT、TX_WAIT 和 READY_SENTINEL。

收到 CQE 时先校验 slot 状态和 generation；DEL/MOD 前的 stale CQE 只消费，不访问旧 handle。

### 9.4 Ready queue 与 ring fd

Linux 6.7 的 io_uring ring fd 在 CQ 有 completion 或 ring 有待处理 work 时报告 `EPOLLIN`。adapter 直接把该 fd 返回给应用，不再增加 eventfd。

初始 readiness 和 `maxevents` 截断由内部 ready queue 表示。若 ready queue 非空但 CQ 已空，adapter 提交至多一个 `IORING_OP_NOP` sentinel，使 ring fd 保持可观察的 `EPOLLIN`；sentinel 只唤醒 drain，不产生用户事件。

### 9.5 CQ 处理

- wait CQE `res == 0` 或 `res == -EAGAIN`：重查 predicate、合并 event、立即 rearm。
- `res == -ECANCELED`：正常取消，只消费。
- 其他负值：该 watch 进入 ERROR，排队一次 `UFIFO_EPOLLERR`，直到 MOD 或 DEL。
- CQ overflow 标志必须通过 `io_uring_enter()` flush；发现 dropped CQE 时 adapter 进入 fatal 状态并返回 `-EOVERFLOW`，不得静默继续。

## 10. Watch 状态机

```text
FREE --ADD--> ACTIVE --wait CQE--> ACTIVE
                  |                  |
                  +------MOD---------+
                  |
                  +--DEL--> CANCELING --sync cancel--> FREE
                  |
                  +--fatal wait error--> ERROR --MOD/DEL--> ACTIVE/FREE
```

### 10.1 ADD

1. 校验参数、重复注册和 capacity。
2. 获取 handle 本地强引用并增加 logical watch count。
3. 分配 slot/generation，arm 所需方向。
4. 检查初始 predicate；成立则进入 ready queue。
5. 批量提交 wait 和必要的 sentinel。
6. 任一步失败必须反向释放 SQE、slot 和引用。

### 10.2 MOD

- 只更新 `data` 时不取消 wait。
- interests 或 threshold 改变时，先同步取消受影响方向，再增加 generation、重查 predicate 并 arm 新 wait。
- MOD 是同一 adapter mutex 下的原子配置切换；drain 不会看到半更新配置。

### 10.3 DEL

- 使用 `IORING_REGISTER_SYNC_CANCEL` 按 `user_data` 同步取消 RX/TX wait。
- `-ENOENT` 表示请求已完成或 CQE 已排队，可视为 kernel 已不再引用 futex 地址。
- 增加 generation，使尚未消费的旧 CQE 失效。
- 清除 ready queue 项并释放 handle 强引用。
- DEL 返回后不得再产生该 registration 的用户事件。

### 10.4 Adapter close

- 调用方先停止所有 ctl/drain 调用。
- 逐 watch 执行 DEL 语义，不向用户返回剩余 ready event。
- close ring fd 前确保 kernel 不再引用任何 handle mapping。
- ring fd、三个 mmap 区域和全部内存只由 adapter close 释放。

## 11. Handle 生命周期
- core 映射与跨进程 destroy/force 契约见 [ufifo v2 单共享内存与 Lifetime 设计](ufifo-v2-single-shm-lifetime.md)。
- ADD 持有本地强引用，并增加 `logical_watch_count`。
- 未 DEL 的 handle 调用 `ufifo_close()` 或 `ufifo_destroy()` 返回 `-EBUSY`，不会隐式留下不可操作的 orphan watch。
- DEL 的同步取消完成后释放引用；之后用户可以 close handle。
- `ufifo_epoll_close()` 自动删除全部 watch，但不会替用户 close `ufifo_t`。
- 该规则比“用户 close 后 adapter 暗中保活”更明确：后者虽然避免 UAF，却会留下用户无法正常消费或 DEL 的 watch。

## 12. 并发与 fork 契约

### 12.1 并发

- 多线程 ctl：支持；通过 adapter mutex 串行修改 watch table 和 SQ。
- drain：只允许单消费者；并发 drain 返回 `-EBUSY`。
- ctl 与 drain：支持；内部按同一状态锁顺序串行关键区。
- adapter close：不与 ctl/drain 并发。
- FIFO close/destroy：不与该 handle 的数据调用或 ctl 并发。

锁顺序固定为：

```text
adapter state mutex -> handle local lifecycle mutex
```

任何路径不得在持有共享 FIFO data/ctrl mutex 时等待 io_uring cancel。

### 12.2 Fork

adapter 保存创建者 PID：

- 子进程调用 fd/ctl/drain 返回 `-ECHILD`；
- 子进程调用 adapter close 只 unmap、关闭自己的 fd 副本并释放本地内存，不向共享 ring 提交 cancel；
- 子进程需要重新 `ufifo_epoll_create()` 并重新 ADD；
- child close path 不获取可能在 fork 时由其他线程持有的 adapter mutex。

## 13. 错误与安全

- `io_uring_setup` 被 seccomp、sysctl 或 LSM 禁止时，原样返回 `-EPERM`/`-EACCES`，不切换旧实现。
- opcode probe 失败返回 `-EOPNOTSUPP`。
- 所有 size/capacity/ring-size 计算先做溢出检查。
- mmap offset、ring offset 和 entry 数量全部校验后再计算地址。
- 公共 reserved 字段必须为零，未知 flag 一律拒绝。
- 日志只记录 errno、watch slot/generation 和 request id；不记录用户 buffer、共享数据或 `data.ptr`。
- adapter 只申请完成任务所需的普通 io_uring，不启用 SQPOLL 或特权模式。

## 14. 文件边界

建议最终拆分：

```text
inc/ufifo.h                 core public API
inc/ufifo_epoll.h           adapter public API
inc/ufifo_layout.h          shared ABI
inc/ufifo_internal.h        core internal contract
src/ufifo_data.c            nonblocking put/get/peek/seek
src/ufifo_wait.c            wait word + blocking loops
src/ufifo_sync.c            mutex/OFD primitives
src/ufifo_epoll.c           public adapter + watch state machine
src/ufifo_uring.c           raw ring setup/submit/CQ/cancel boundary
src/ufifo_uring.h           private raw ring declarations
test/ufifo_core_test.cpp
test/ufifo_wait_test.cpp
test/ufifo_epoll_test.cpp
test/ufifo_lifecycle_test.cpp
```

删除：

```text
src/ufifo_broker.c
src/ufifo_broker_main.c
ufifo-broker CMake/install target
旧 eventfd helper、字段、API、示例和 broker tests
```

## 15. 实施与验证

阶段提交、测试矩阵、性能门槛、完成标准和风险登记见
[ufifo-v2-blocking-epoll-validation.md](ufifo-v2-blocking-epoll-validation.md)。

## 16. 参考依据

- Linux 6.7 `io_uring/futex.c`：`IORING_OP_FUTEX_WAIT` 的 shared futex、字段校验、`EAGAIN` 和 cancel 行为：<https://github.com/torvalds/linux/blob/v6.7/io_uring/futex.c>
- Linux 6.7 `io_uring/io_uring.c`：ring fd 的 poll 实现，CQ/work 对应 `EPOLLIN`，SQ 空间对应 `EPOLLOUT`：<https://github.com/torvalds/linux/blob/v6.7/io_uring/io_uring.c>
- Linux 6.7 UAPI `io_uring.h`：SQE/CQE、opcode、feature 与 register ABI：<https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/io_uring.h>
- Linux 6.7 futex internal contract：当值不等于 expected 时不会入睡，以及 6.7 仅实现 32 位 futex：<https://github.com/torvalds/linux/blob/v6.7/kernel/futex/futex.h>
- liburing upstream manual（仅作为 ABI 说明，不作为依赖）：<https://man7.org/linux/man-pages/man3/io_uring_prep_futex_wait.3.html>
- 同步取消 ABI：<https://man7.org/linux/man-pages/man3/io_uring_register_sync_cancel.3.html>
