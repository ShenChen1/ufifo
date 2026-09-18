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
- 非 ABI 3 对象明确返回 `-EPROTO`，不提供 legacy/broker 路径。

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
| 旧共享布局混用 | layout ABI 3 校验，attach/force 返回 `-EPROTO` |
