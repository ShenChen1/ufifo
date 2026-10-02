# 原子表示变更提交边界

日期：2026-10-02。

## Problem 1-Pager

- Context：C 使用 `_Atomic`，C++ 使用普通标量和 GCC `__atomic`，共享字段有两种声明方式。
- Problem：相同共享内存的类型表示和初始化接口分叉，增加互操作和维护成本。
- Goal：提交已有的普通标量 + GCC builtin 表示，让 C/C++ 使用同一套内部接口。
- Non-Goals：不弱化内存序、不改变 futex 协议、不纳入 role、TSan 配置或测试归并。
- Constraints：保留共享布局 ABI 4，运行期间并发访问仍必须使用原子封装；初始化在对象发布前完成。

## 方案和假设

- 保留 C11/C++ 双表示：运行时 lock-free 检查仍在，但两套声明和初始化必须继续维护。
- 普通标量 + GCC builtin：表示统一，初始化更直接；依赖编译器扩展和目标架构 lock-free 能力。

选择第二项，提交现有工作区方案；不声称可移植到所有 C11 编译器或架构。
本方案移除 create/attach 的运行时 lock-free 检查，目标平台必须支持 bool、size_t、uint32_t 的天然对齐 lock-free 原子操作。
回归测试核对当前构建目标的能力；不将测试通过描述为生产代码对任意不支持平台的拒绝保证。

影响说明：替换 `utils.h` 的类型和宏，移除 `_Atomic` 初始化及运行时能力检查；
尚未归并的旧 wait 测试改用 relaxed store 初始化；普通字段直接写入只限发布前。
SC arm、after-arm recheck、notify fence、release publish 及所有既有 load 内存序保持不变。

## 验证

独立提交版本的 Release、ASan/UBSan 全量 CTest 均为 555 项：509 通过、46 按契约跳过、0 失败。
ASan 使用 `detect_leaks=0`，UBSan 使用 `halt_on_error=1`；新增测试核对 lock-free 能力及 CAS 成功/失败行为。
x86_64 和 AArch64 的 C 编译检查确认三个 typedef 为普通标量，且目标编译器报告这些宽度 always-lock-free。
测试不构成弱内存证明；真实 AArch64 运行和远端 CI 不在本次验证范围内。
