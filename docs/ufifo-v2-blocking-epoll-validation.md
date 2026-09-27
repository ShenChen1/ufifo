# ufifo v2 Blocking 与 Epoll 实施和验证计划

本文是 [ufifo v2 Blocking 与 Epoll 重构设计](ufifo-v2-blocking-epoll-design.md)的配套执行计划。

## 1. 实施顺序

最终分支不保留双轨实现或 feature flag；阶段提交只用于记录实现过程，不作为可发布兼容态。

1. **测试契约**：拆分测试文件，加入 wait word、blocking 和新 adapter 的失败测试。
2. **共享 ABI/Core**：加入 wait word 与 futex primitive，blocking API 一次性切换并删除 blocking eventfd。
3. **单 SHM/Lifetime**：合并 control/data 映射，以 OFD lock 仲裁 attach、destroy 和 force。
4. **Raw ring engine**：实现 setup/probe/mmap/SQ/CQ/sync-cancel 的私有边界测试。
5. **Adapter**：实现 public API、watch 状态机、ready queue、fork 与生命周期规则。
6. **删除旧架构**：删除 broker、eventfd API/字段/target 及旧测试。
7. **文档与示例**：更新 README、pkg-config/install 和 epoll example。
8. **完整验证**：clean build 后执行功能、并发、sanitizer、跨进程和性能验证。

## 2. 测试矩阵

### 2.1 Blocking

- empty/full 的无限等待和严格超时；
- arm-before-wait、notify-before-kernel-queue、spurious wake；
- 多 reader/multi writer 广播唤醒；
- SOLE/SHARED × NONE/THREAD/PROCESS；
- waiter SIGKILL 后下一次 notify 清理 stale ARMED；
- reset、reader close/reap、attach 释放容量；
- EINTR、ETIMEDOUT、EAGAIN。

### 2.2 单 SHM/Lifetime

- 单名字、单 fd、单 mmap，control/data 偏移与文件边界一致；
- active attach 时 destroy/force 返回 `-EBUSY`，原 handle 保持可用；
- 最后一个其他 handle close 或崩溃后 destroy/force 成功；
- attach 与 force 并发只得到单一完整代，不混合 inode；
- attach 对非法 ABI 4 布局返回 `-EPROTO`；force 在取得 exclusive lifetime lock 后直接替换对象。
- fork child 使用继承 core handle 返回 `-ECHILD`，不影响 parent lifetime/user slot。
- robust data mutex owner death 后，下一个 locker 清空不确定数据并返回 `-EOWNERDEAD`，后续操作恢复正常。

### 2.3 Adapter happy path

- 空 FIFO 无事件；put 产生 IN；get 产生满足 threshold 的 OUT；
- ADD 时已经 ready；
- IN+OUT mask 合并；
- SHARED 多 consumer 广播；SOLE 竞争后允许 spurious completion；
- drain 后立即 rearm，持续压力下无丢事件；
- ready queue 超过 `maxevents` 时 ring fd 仍保持可唤醒。

### 2.4 Adapter failure/lifecycle

- ADD/MOD/DEL 参数、重复项、capacity 满；
- DEL 与已完成但未消费 CQE 竞态；
- MOD threshold/interests 与 CQE 竞态；
- close handle while watched 返回 `-EBUSY`；
- adapter close 自动取消全部 wait；
- 不支持 opcode、io_uring 被禁用、mmap/setup 失败；
- CQ overflow/dropped 不静默；
- fork child 返回 `-ECHILD`，child close 不影响 parent；
- 多线程 ctl + 单 drain，无重复释放、死锁或 UAF。

### 2.5 验证层级

1. clean `cmake` configure/build；
2. 全量 CTest；
3. ASan+UBSan；
4. TSan（单独构建，记录环境不支持项）；
5. 跨进程 crash/reap 测试；
6. `strace`/`ps` 验证不再创建 broker、UDS 或 eventfd；
7. Linux 6.7 原生运行验证，不用较新内核结果代替最低版本证据；
8. benchmark 比较无 waiter、blocking、epoll burst 三类路径。

## 3. 性能验收

- 无 waiter 的 nonblocking put/get 不得出现 syscall。
- 无 waiter 热路径相对当前基线的吞吐回退目标不超过 3%；超过则停止合并并分析 cache line/atomic 成本。
- burst 中一个 adapter wait 在 drain 前最多产生一个 futex completion。
- 不用 UDS/eventfd 结果推断 futex/io_uring 性能；必须分别测量。
- benchmark 报告 CPU affinity、payload、模式、锁类型、进程/线程拓扑和内核版本。

### 3.1 全局 armed-epoch 实验结果（2026-09-26）

在 Linux 7.0 x86-64、Intel i5-13500H、固定线程 affinity 下运行 `ufifo_bench scale=1`。
基线是当前 HEAD 两轮均值，实验列是一轮全局 RX/TX armed-epoch；数值为 ops/s：

| 场景 | 基线 | 实验 | 变化 |
| --- | ---: | ---: | ---: |
| PingPong/nolock/4B | 11.19M | 11.17M | -0.2% |
| SPSC/nolock/4B | 14.44M | 12.01M | -16.8% |
| SPSC/nolock/256B | 15.61M | 12.11M | -22.4% |
| SharedSPSC/4B | 8.28M | 6.15M | -25.8% |
| SharedSPSC/256B | 8.02M | 5.21M | -35.0% |

该实验通过正确性与 TSan 聚焦验证，但没有达到 3% 性能门槛。SharedSPSC 的主要成本是
多个 reader 在容量边界前进时修改同一个 TX epoch；只在 `cached_min_out` 实际前进时
发布 TX 已减少无效 RMW，但没有消除共同原子字的所有权迁移。

### 3.2 SC predicate + 条件通知实验结果（2026-09-26）

环境、affinity 和 `scale=1` 与 3.1 相同；实验值为两轮均值。该版本在 wait word 未
armed 时只执行 SC load，不修改 epoch；readiness predicate 的发布和复查改为 SC：

| 场景 | 基线 | always-RMW | SC 条件通知 | 相对基线 |
| --- | ---: | ---: | ---: | ---: |
| PingPong/nolock/4B | 11.19M | 11.17M | 10.87M | -2.8% |
| SPSC/nolock/4B | 14.44M | 12.01M | 13.80M | -4.4% |
| SPSC/nolock/256B | 15.61M | 12.11M | 11.64M | -25.5% |
| SharedSPSC/4B | 8.28M | 6.15M | 5.64M | -31.8% |
| SharedSPSC/256B | 8.02M | 5.21M | 5.47M | -31.8% |

正确性方面，常规 CTest 453/453 通过（45 个参数组合按契约跳过）；TSan 聚焦执行
264 个用例，255 个通过、9 个按契约跳过且无 race 报告；AArch64 交叉构建成功，QEMU
下 12 个 wait/竞态用例通过。QEMU 只作为功能与代码生成证据，不代表真实弱内存硬件。

该版本仍未达到 3% 门槛。x86-64 上 SC index store 生成带锁交换，避免 wait-word RMW
并未消除 hot-path RMW，只是把成本移到 `in/out/cached_min_out`，因此不建议作为最终方案。

### 3.3 C11 release predicate + SC fence 实验结果（2026-09-26）

该版本把共享并发字段统一为 C11 `_Atomic`，索引继续用 release store 发布。publisher 在
观察 wait word 前执行一个 `atomic_thread_fence(memory_order_seq_cst)`；waiter 使用 SC RMW
arm 和 SC predicate recheck。没有增加 waiter count、额外状态字或索引打包。

环境、affinity 和 `scale=1` 与 3.1 相同；实验值为两轮均值：

| 场景 | 基线 | always-RMW | SC predicate | C11 fence | 相对基线 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PingPong/nolock/4B | 11.19M | 11.17M | 10.87M | 11.32M | +1.1% |
| SPSC/nolock/4B | 14.44M | 12.01M | 13.80M | 11.99M | -17.0% |
| SPSC/nolock/256B | 15.61M | 12.11M | 11.64M | 11.26M | -27.9% |
| SharedSPSC/4B | 8.28M | 6.15M | 5.64M | 6.17M | -25.5% |
| SharedSPSC/256B | 8.02M | 5.21M | 5.47M | 5.79M | -27.8% |

常规 CTest 454/454 通过（45 个参数组合按契约跳过）。TSan 聚焦执行 264 个用例，
255 个通过、9 个按契约跳过且无 race 报告。AArch64 交叉构建成功，QEMU 下 13 个
wait/竞态/ABI 用例通过；反汇编确认 x86-64 fence 为 locked operation，AArch64 为
`dmb ish` 后接 `ldar`。QEMU 仍只作为功能与代码生成证据，不代表真实弱内存硬件。

TSan 结果存在重要限制：GCC 15.2 的目标文件确实引用 `__tsan_atomic_thread_fence`，但
优化构建同时明确警告 `atomic_thread_fence is not supported with -fsanitize=thread`。
因此“生成了 TSan hook”和“TSan 能完整证明 fence 同步”不是一回事；本次无 race 报告
不能消除该工具盲区，也不能把动态压力测试提升为内存模型证明。

该版本没有达到 3% 性能门槛。它比 SC predicate 避免了 x86 索引 locked store，但把
SC fence 放在每次 publisher 通知检查前；真实双线程 SPSC 和 SHARED 路径仍承担跨核
排序与 cache-line ownership 成本。因此它只作为独立正确性 checkpoint 合入，不作为
最终性能验收结论。

### 3.4 Nonblocking fast path 与 fence 提交前复验（2026-09-27）

复验使用同一份预编译 benchmark 可执行文件、同一台 12 CPU 主机、固定 affinity、
`scale=1` 和 5 次重复中位数，仅切换动态链接的库实现。这样避免不同 benchmark 源码或
单次测量把实现差异放大。数值为 ops/s：

| 场景 | master | nonblocking fast path | C11 fence | fence 相对 fast path | fence 相对 master |
| --- | ---: | ---: | ---: | ---: | ---: |
| PingPong/nolock/4B | 91.22M | 89.93M | 95.66M | +6.4% | +4.9% |
| PingPong/nolock/256B | 93.53M | 94.98M | 91.05M | -4.1% | -2.7% |
| Burst/nolock/4B | 167.06M | 159.93M | 96.28M | -39.8% | -42.4% |
| Burst/nolock/256B | 100.19M | 101.91M | 85.18M | -16.4% | -15.0% |

PingPong 的差值落在本次 4.8%--11.6% spread 附近，不能解释为稳定收益；Burst 退化则
远超噪声和 3% 门槛。原因是无 waiter 时虽然不写 wait word、不调用 futex，publisher
仍在每次通知检查前执行 SC fence。nonblocking fast path 本身不执行 fence，但成功的
put/get 在 publish 后仍进入通知检查，因此 Burst 仍承担 fence 成本。

提交前验证结果：Release CTest 459/459 通过；五个 wait/lost-wakeup/共享 epoch 核心
用例各重复 100 轮通过；TSan CTest 459/459 通过且无 race 报告，但保留 3.3 所述 fence
建模限制；AArch64 交叉构建成功，QEMU 下 22 个 wait/竞态/ABI 用例通过。AArch64
反汇编确认通知路径包含 `dmb ish`、随后为 `ldar`。这些结果支持实现与代码生成，仍不
替代真实弱内存硬件的长期压力测试。

## 4. 完成标准

- 源码、公开头文件、构建系统、README、示例和测试中不再存在 broker/eventfd 通知路径。
- blocking API 的超时、崩溃和无丢唤醒回归测试通过。
- control/data 位于一个 shm inode，destroy/force 不会越过活跃 handle。
- adapter API 不暴露任何 io_uring 类型。
- ADD/MOD/DEL、初始 readiness、backlog、cancel、fork 和 close 契约均有测试。
- 所有被修改的源码文件满足 500/80/5/10 限制。
- Linux 6.7+ runtime probe 失败时明确报错，不 fallback。
- 功能证据与性能证据分别记录；未运行的最低内核或 sanitizer 验证不得声明通过。

## 5. 主要风险

| 风险 | 缓解 |
| --- | --- |
| raw io_uring ring memory ordering错误 | 独立 engine、小接口、参考 UAPI barrier、压力与 sanitizer 测试 |
| DEL/CQE 竞态导致 UAF | sync cancel、generation token、无裸指针 user_data、强引用 |
| ready queue 有事件但 ring fd 不 readable | 单个 NOP sentinel 保持唤醒 |
| SOLE 多消费者惊群 | 先保证正确；以 benchmark 决定是否增加 wake chaining，不能牺牲语义 |
| 32 位 epoch ABA | 明确运行边界；arm-to-wait 窗口不可能完成 `2^31` 次有效 notify |
| io_uring 被系统策略禁用 | create 明确失败；不 fallback、不影响纯 core API |
| 旧共享布局混用 | attach 通过 layout ABI 4 拒绝；force 明确替换名字对应对象 |
