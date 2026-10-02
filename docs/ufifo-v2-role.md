# role 提交边界

日期：2026-10-02。

## Problem 1-Pager

- Context：开发工作区已有 producer/consumer/duplex 角色；此前纯 futex 重构未纳入这些权限变化。
- Problem：shared 的生产者也登记为消费者，会成为不会前移的最慢游标；测试和示例需要人工消费来绕过。
- Goal：提交已有 role 能力边界、slot 生命周期、权限检查和配套验证。
- Non-Goals：不改变 futex 握手、原子内存序、TSan 配置或测试目录组织。
- Constraints：默认零值为 duplex；生产者支持 reset；consumer reset 仍保留既有允许行为。

## 方案与决定

- 继续人工推进生产者消费游标：无需新增角色，但混淆读写职责，容易让广播队列自阻塞。
- 显式 role：生产者不登记 receive slot，读写能力在等待前校验；需同步更新示例和测试。

选择第二项，提交现有工作区实现。开发阶段不承诺旧二进制初始化对象的兼容性，使用新头文件重新编译。
role 属于本地 handle，不写入共享布局；shared layout ABI 不变。

## 行为与影响

- duplex：默认，登记消费者 slot，保留读写能力。
- producer：不占消费者 slot；允许 put/reset，get/peek/skip/seek 返回 `-EPERM`。
- consumer：登记 slot，允许消费；所有 put 入口返回 `-EPERM`。
- producer 的 shared `out` 指向 cached minimum，sole 指向全局 receive position；关闭时不注销其他消费者。
- reset 的并发边界不扩大；LOCK_NONE 仍需外部协调复制和位置重置，测试只在写者等待空间时 reset。

影响说明：open 配置角色、注册和 kfifo 位置；操作层在等待前检查能力；
SPMC 示例和拓扑测试移除生产者人工消费；SharedSPSC benchmark 改为每条数据一次 put、一次 get。
旧“三次 API 操作/条”的吞吐结果与新计数不可直接当作同口径性能提升比较。

## 验证

纳入 role 合同测试及 42 项 sole/shared × 三种 lock 的 publisher/等待测试，覆盖生产者 reset 唤醒写者。
等待测试通过有界 arm 同步和 timed write 保证失败路径可 join；测试 helper 作为必要配套提交。
保留 HEAD 测试清单，不纳入目录归并；独立版本 Release、ASan/UBSan 全量 CTest 各 601 项：552 通过、49 按契约跳过、0 失败。
ASan 使用 `detect_leaks=0`，UBSan 使用 `halt_on_error=1`；46 项 role/等待测试重复 20 轮无失败。
SharedSPSC 小规模运行完成 1024 条消息，计数为 2048 次 API 操作；只检查运行和计数，不作为性能对比。
测试不构成弱内存证明，未验证远端 CI。
