# 测试组织

目录按职责分类，而非运行级别。真实实现测试链接到 `ufifo_test`；等待协议的边界替身测试单独链接到
`ufifo_wait_protocol_test`，避免 `--wrap` 替换影响真实集成测试。两者均由 CTest 自动发现。

| 目录 | 职责 |
| --- | --- |
| `contract/` | 公共 API、errno、角色权限和共享内存布局契约 |
| `data/` | 记录、标签和共享读游标的数据语义 |
| `wait/` | 等待字、谓词、容量发布策略、真实等待集成与隔离的协议测试 |
| `concurrency/` | SPSC/SPMC/MPSC/MPMC 拓扑与无锁丢唤醒压力测试 |
| `lifecycle/` | 句柄与对象生命周期、死用户回收、崩溃及锁恢复 |
| `support/` | 公共适配器、配置矩阵、有界同步工具及其自测 |
| `cmake/` | 构建选项的脚本测试，独立注册到 CTest |
| `benchmark/` | 基准工具及命令行自测；性能测量不计入 CTest 正确性结果 |

## 整理决策（ADR）

- 背景：等待分层与回归增加后，同类测试散落在多个小文件中，公共同步编排出现重复。
- 问题：按“新增回归”命名文件难以定位职责，睡眠猜测线程状态会掩盖同步覆盖不足。
- 目标：按机制合并测试文件，复用明确且有截止时间的 ARMED 等待，保留独立失败报告。
- 非目标：不修改生产代码，不删减锁、数据格式、模式组合，也不把真实 futex 测试替换为协议替身。
- 约束：保留已有测试名称；单文件不超过 500 行；线程先 join 再做致命断言，进程必须有界回收。

比较“仅移动文件”和“按职责合并并复用编排”：前者风险小但不能减少重复，后者需要逐项核对覆盖。
这里选择后者。兼容假设是现有 GoogleTest 名称仍供过滤器使用，所以文件移动不重命名测试套件。

新增回归应优先放入对应机制文件，不再为每个缺陷创建一个 `*_regression_test.cpp`。
只有配置改变、而预期语义相同的用例才参数化；不同契约继续分别断言。
主测试每项 CTest 的兜底超时为 45 秒（拓扑内部截止时间为 30 秒），协议替身测试为 5 秒。

## 构建与运行

构建全部目标后运行完整套件（包含协议测试、构建选项测试和示例）：

```sh
cmake -S . -B build
cmake --build build -- -j2
ctest --test-dir build --output-on-failure
```

按名称筛选等待测试（文件归并保留了部分历史套件名），或者只运行协议测试：

```sh
./build/bin/ufifo_test --gtest_filter='*Wait*:*Predicate*:*Timeout*:*WakesBlockedWriter'
ctest --test-dir build -R UfifoWaitProtocolTest --output-on-failure
```

## 性能基准

构建并运行基准，默认重复五次：

```sh
cmake --build build --target ufifo_bench -- -j2
./build/bin/ufifo_bench 1 --repetitions=5
```

The harness uses `steady_clock`, pins every measured thread before opening a start gate, alternates suite order, and
reports the median. `Spread` is `(maximum - minimum) / median`; a large value marks a noisy result rather than a
precise regression. Use an odd repetition count. `--no-pin` is available only for environments that reject CPU
affinity, and `--json` emits the format consumed by CI. `SharedSPSC` counts all three API operations performed per
item: one put plus the producer and consumer gets. CI produces all results but applies its regression gate only to the
lower-noise single-threaded `PingPong` and `Burst` families.
