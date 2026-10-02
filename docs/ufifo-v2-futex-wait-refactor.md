# ufifo v2 futex 等待协议重构设计

状态：结构分层已落地；实施与验证见 `ufifo-v2-futex-refactor-implementation.md`
日期：2026-09-29
范围：当前开发分支中的阻塞、超时、唤醒及其与数据发布、锁和生命周期的关系
结论：先做保持行为不变的结构重构；不替换现有 lost-wakeup 协议

## 1. Problem 1-Pager

### Context

`kfifo` 已经把无锁数据搬运路径收敛成了成熟、很小的一组操作：生产者发布 `in`，消费者发布 `out`，另一侧以 acquire 或更强顺序读取相应位置。真正难读的部分不在环形缓冲区，而在“条件不满足以后怎样睡眠，以及条件改变以后怎样保证一定能被看见”。

当前 futex 相关逻辑分散在：

- `src/ufifo_wait_word.c`：arm、futex syscall、notify；`src/ufifo_wait.c`：RX/TX 等待策略；
- `inc/ufifo_predicate.h`：读写谓词；`src/ufifo_capacity.c`：cached-min 维护；`src/ufifo_opts.c`：数据发布；
- `src/ufifo_state.c`：reset、skip、seek 带来的状态改变；
- `src/ufifo_init.c`：注册、注销和共享消费者最小游标更新；
- `src/ufifo_sync.c`：锁恢复、owner-death 恢复和补偿唤醒；
- `inc/kfifo.h`、`inc/utils.h`：数据位置和原子操作的内存序。

这些代码单独看都不长，但正确性依赖它们组成的完整链条：

```text
predicate -> arm -> recheck -> unlock -> futex wait -> relock -> retry
                         ^
publish -> notify -------+
```

### Problem

目前很难只通过一个文件回答以下问题：

1. 哪个字段才是“有数据/有空间”的事实来源？
2. wait word 是条件本身，还是只是一种通知状态？
3. 为什么 arm 之后必须用更强的顺序重新检查谓词？
4. reset、close、死消费者回收是否都覆盖了唤醒路径？
5. 超时发生在加锁、futex wait 或重新加锁时，语义是否一致？

这种可读性问题会增加误改内存序或漏掉 notify 的风险，而这两类错误都可能表现为极低概率永久睡眠。

### Goal

- 给当前实现建立一个可独立阅读的正确性模型；
- 明确 RX/TX 两条等待链的事实来源、发布点和通知点；
- 把 lost-wakeup 不变量写成可审查的规则；
- 给出小步、保持行为不变的重构边界和验证标准；
- 让后续性能优化先证明不破坏协议，再比较吞吐和延迟。

### Non-Goals

- 本文不改变公开 API、共享内存布局或现有行为；
- 不重新设计 `kfifo` 数据面；
- 不引入 eventfd、epoll、io_uring 或后台 broker；
- 不承诺进程死亡时立即唤醒另一进程；
- 不在本阶段用“更快”的 acquire-only 握手替换当前协议。

### Constraints and assumptions

- 项目仍在开发阶段，因此本轮不以 ABI 兼容为约束；
- 生产者允许调用 reset，reset 后必须能释放写侧等待；
- `UFIFO_LOCK_NONE` 也必须满足等待协议，不能依赖 mutex 偶然建立顺序；
- 本次纯重构保留 HEAD 的 C11 `_Atomic` 表示及 C++ GCC builtin 兼容层；role、原子表示替换和快路径内存序优化仍未提交；
- 单元测试、TSan 和 QEMU 都是证据的一部分，但都不是弱内存硬件上的形式化证明。

## 2. 先记住三个结论

### 2.1 环形位置是事实，wait word 不是

- “有数据”的事实是读者观察到可消费的已发布 `in`；
- “有空间”的事实是写者根据 `in` 和有效 `out` 计算出的 unused length；
- `rx_wait` / `tx_wait` 只记录“可能有人正在等”和一个 epoch。

因此，每次 futex 返回后都必须重新检查谓词。唤醒可能是多余的，futex 也允许虚假返回；任何一次 wake 都不代表操作已经可以完成。

### 2.2 futex 只解决“比较并入队”，不自动解决跨原子的 lost-wakeup

`FUTEX_WAIT_BITSET(addr, expected, ...)` 会在内核中原子地检查 wait word 是否仍等于 `expected`，相等才睡眠。这能关闭“notify 改了同一个 wait word，而 waiter 正准备入队”的窗口。

但谓词和 wait word 是两个不同的原子对象。若一侧只看谓词，另一侧只看 wait word，两边都可能读到旧值。futex 本身不会替我们建立这两个对象之间的顺序。

### 2.3 正确性属于整条链，不能只审查某个 atomic

完整协议必须一起检查：

```text
等待侧：读谓词 -> arm wait word -> 强重新检查谓词 -> futex(expected epoch)
发布侧：release 发布谓词 -> SC fence -> 观察 wait word -> 改 epoch并 wake
```

只把其中一次 load 改成 acquire、只在某个路径补 wake，或者只证明 futex syscall 没有竞态，都不足以排除 lost-wakeup。

## 3. 数据与角色模型

### 3.1 关键状态

| 状态 | 含义 | 谁发布 | 谁观察 |
| --- | --- | --- | --- |
| `kfifo.in` | 已完成写入的数据尾部 | 生产者，release | 消费者，acquire/SC |
| sole `out` | 单消费者已释放的数据头部 | 消费者，release | 生产者，acquire/SC |
| per-user `out` | 每个共享消费者的进度 | 对应消费者，release | 最小值维护逻辑 |
| `cached_min_out` | 共享模式下生产者使用的最慢消费者位置 | 消费者、注册/注销、回收逻辑 | 生产者，acquire/SC |
| `rx_wait` | 读者等待 epoch | 读者 arm，写者 notify | futex RX 协议 |
| `tx_wait` | 写者等待 epoch | 写者 arm，释放空间的一侧 notify | futex TX 协议 |

### 3.2 两条对称但不完全相同的等待链

| 方向 | waiter | 谓词 | publisher | wait word |
| --- | --- | --- | --- | --- |
| RX | 消费者 | 当前记录/字节可读 | 成功写入的生产者 | `rx_wait` |
| TX | 生产者 | unused length 足够 | 消费、skip、seek、reset、注销、回收 | `tx_wait` |

RX 的事实来源比较直接：生产者推进 `in`。TX 在 shared 模式更复杂：真正限制空间的是所有存活消费者中的最小 `out`，生产者热路径优先读取 `cached_min_out`，必要时才扫描或回收。

### 3.3 待独立提交的 `role` 不改变协议

- 工作区的 producer role 允许 put/reset，不占消费者 slot；
- 工作区的 consumer/duplex handle 按其角色拥有消费者位置和消费能力；
- role 校验应在进入等待协议之前失败；这些权限变化不属于本次纯重构提交；
- 一旦进入 RX 或 TX 等待，使用的仍是同一套 arm/recheck/notify 协议。

特别地，生产者 reset 会把 FIFO 恢复为空，因此它改变的是 TX 谓词：可能从“空间不足”变为“空间足够”，所以当前行为是通知写者，而不是把 reset 当成普通写入去通知读者。

## 4. wait word 状态机

wait word 使用最低位表示是否 armed，其余位形成递增 epoch：

```text
偶数 E：idle，当前 epoch 未标记 armed
   | waiter fetch_or(1)
   v
奇数 E+1：armed，至少有 waiter 声明可能睡眠
   | publisher CAS(E+1 -> E+2), futex_wake(INT_MAX)
   v
偶数 E+2：新的 idle epoch
```

规则如下：

1. waiter 用 SC read-modify-write 设置最低位，并保存返回后的奇数 epoch；
2. 多个 waiter 可以观察并等待同一个奇数 epoch；
3. publisher 只在观察到奇数时 CAS 到下一个偶数 epoch；
4. CAS 成功者执行 `FUTEX_WAKE`，当前选择唤醒全部 waiter；
5. CAS 失败后使用返回的 observed 重试；若已变为偶数就退出，若仍为奇数则尝试推进该 epoch；
6. 超时或进程退出可以留下一个过期的奇数状态；这不影响正确性，下一次 publisher 会把它推进到偶数，最多产生一次无人接收的 wake syscall。

wait word 不记录精确 waiter 数量。32 位 epoch 会回绕，不能声称排除跨完整回绕周期的 ABA。

## 5. 当前调用链

### 5.1 put：等待空间并发布数据

```text
ufifo_put[_timeout]
  -> handle/参数检查
  -> 生成一次绝对 deadline
  -> 获取 data lock
  -> __ufifo_tx_available_fast()      # 本次保留 HEAD 的 SC 读取
  -> 若空间不足：__ufifo_wait_for_space()
       -> shared 模式刷新 cached_min / 回收死消费者
       -> __ufifo_wait_arm(tx_wait)    # SC RMW
       -> __ufifo_tx_available_after_arm() # SC 重新检查
       -> 若仍不足：解锁 -> futex wait -> 带同一 deadline 重新加锁
       -> 循环重查
  -> kfifo 写入并 release 发布 in
  -> __ufifo_notify_readers()         # RX notify
  -> 解锁
```

第一次 unused-length 检查可以独立评估是否改成 acquire：若快路径已满足就不睡眠，arm 后的 SC 重新检查才承担 lost-wakeup 正确性责任。本次只分层，仍保留 HEAD 的 SC 读取。

### 5.2 get：等待数据并释放空间

```text
ufifo_get[_timeout]
  -> handle/参数检查
  -> 生成一次绝对 deadline
  -> 获取 data lock
  -> 检查可读长度
  -> 若无数据：__ufifo_wait_for_data()
       -> SC 检查 in
       -> __ufifo_wait_arm(rx_wait)    # SC RMW
       -> SC 重新检查 in
       -> 若仍为空：解锁 -> futex wait -> 带同一 deadline 重新加锁
       -> 循环重查
  -> kfifo 读取并 release 发布 out
  -> sole：通知写者
     shared：只有 cached_min_out 真正前移时通知写者
  -> 解锁
```

shared 消费者推进自己的 `out` 不一定释放全局空间。只有最慢消费者位置前移，TX 谓词才可能变真，所以通知点绑定到 `cached_min_out` 的有效推进。

### 5.3 其他 TX publisher

除正常 get 外，以下路径也可能让写者获得空间：

- `ufifo_skip` / `ufifo_seek` 推进消费者位置；
- `ufifo_reset` 把逻辑位置重置为空；
- shared 消费者 unregister/close 后重新计算最小位置；
- 注册或 attach 改变有效消费者集合并推进 cached minimum；
- 写等待路径发现并回收死消费者；
- robust data lock owner-death 恢复重置状态；
- ctrl lock owner-death 恢复消费者表并推进 cached minimum。

重构时必须按“是否可能让谓词由 false 变 true”审计 notify，而不能只搜索 get/put。

## 6. lost-wakeup 是怎样发生的

考虑写者 W 等空间，消费者 C 刚刚释放空间。若使用弱化协议：

```text
W: 读取空间不足
C: release 发布新 out
C: acquire 读取 tx_wait，仍看见 idle，因此不 wake
W: arm tx_wait
W: acquire 重新读取 out，仍看见旧值，因此进入 futex wait
```

此时空间实际已经足够，但 C 不会再次发布，W 又已经睡下。这就是永久 lost-wakeup。

关键问题不是任意单次原子操作“非原子”，而是：

- C 没看到 W 的 arm；
- W 又没看到 C 的 publish；
- 两个观察发生在不同原子对象上；
- 没有全局顺序迫使至少一方看到另一方。

mutex 模式可能让很多实际执行序列自然串行化，但 `UFIFO_LOCK_NONE` 没有这层保护，并且共享内存等待协议不应有两套正确性证明。因此当前实现统一保留强握手。

## 7. 当前协议为什么排除上述结果

定义事件：

- `P`：publisher 对谓词状态做 release publish；
- `F`：publisher 在 notify 路径执行 SC fence；
- `N`：publisher 用 SC load 观察 wait word；
- `A`：waiter 用 SC RMW arm wait word；
- `R`：waiter arm 后用 SC load 重新检查谓词。

程序顺序给出：

```text
P -> F -> N
A -> R
```

若 publisher 没看见 arm，即 `N` 在 SC 顺序中位于 `A` 之前；若 waiter 重新检查又没看见 publish，则 fence/publish 与 SC recheck 的顺序要求会迫使 `R` 位于 `F` 之前。组合起来会形成：

```text
F -> N -> A -> R -> F
```

这是不可能的环。因此两种结果至少发生一种：

1. publisher 看见 armed wait word，推进 epoch 并 wake；
2. waiter 在 arm 后的强重新检查中看见谓词已经成立，不进入 futex。

这也是为什么不能把 after-arm 的谓词 load 随意降成 acquire，或删除 publisher 的 SC fence。它们不是“为了更保险”的装饰，而是跨谓词原子和 wait-word 原子的握手部分。

当前实现中的对应关系：

- RX publish：生产者 release 发布 `in`；
- RX recheck：消费者 arm 后 SC 读取 `in`；
- TX publish：消费者 release 发布 `out`，或 release/SC 更新 `cached_min_out`；
- TX recheck：生产者 arm 后 SC 读取有效 `out`/`cached_min_out`；
- notify：SC fence，SC load wait word，CAS 奇数到下一偶数，再 futex wake。

## 8. futex、锁与 timeout 的边界

### 8.1 futex 返回不是成功条件

当前等待封装将以下情况交给外层循环处理：

- 正常 wake；
- `EAGAIN`：入内核前 epoch 已变化；
- 虚假返回。

`EINTR` 和 timeout 作为明确错误返回。无论因何返回，只要继续执行操作，就必须重新持锁并重新读取谓词。

### 8.2 解锁和重新加锁

等待路径在 futex syscall 前释放 data lock，返回后再获取。内部结果必须明确记录“当前是否持锁”，避免上层错误地二次 unlock，或在未持锁时访问需要锁保护的状态。

`UFIFO_LOCK_NONE` 下 lock/unlock 是 no-op，但调用结构保持相同，因此协议不会因锁模式出现两套控制流。

### 8.3 一个操作只生成一次绝对 deadline

timeout 覆盖完整操作，而不只是 futex syscall：

```text
初次获取 data lock + 多轮 predicate/wait + 每次重新获取 data lock
```

deadline 在公开操作入口生成一次，使用 `CLOCK_MONOTONIC` 的绝对时间，并在所有阶段复用。每轮等待重新计算相对 timeout 会让总耗时无限延长，是不能接受的语义变化。

## 9. 生命周期与故障恢复

### 9.1 peer death 不是 futex 事件

某个进程退出不会自动修改另一个进程正在等待的 futex word。当前语义只保证后续操作可通过 lifetime/slot 检查发现并回收死消费者；不保证在完全没有后续活动时立即唤醒一个已经睡眠的 peer。

若未来要提供“peer death 立即唤醒”，需要新增独立机制和语义，不应伪装成一次普通 notify 重构。

### 9.2 robust mutex owner death

owner-death 恢复可能重置数据位置或修复消费者表。恢复完成后必须按其改变的谓词执行补偿通知：

- 数据状态重置可能影响 RX 和 TX，因此当前恢复路径通知两侧；
- cached minimum 推进只影响 TX，因此通知写者。

### 9.3 producer reset

生产者 reset 是明确支持的行为。它必须：

1. 校验 handle 后进入正常同步边界（当前 reset 不额外限制 role）；
2. 一致地重置 `in`、有效 `out` 及 shared cached minimum；
3. 发布新状态后通知 TX waiter；
4. 不把 reset 后的空状态误报成 RX 可读。

## 10. 当前代码的主要可读性问题

1. **事实、策略和 syscall 混在一起**：空间计算、死消费者回收、arm、解锁和 futex 都在等待路径附近，读者很难区分哪一步属于正确性协议。
2. **内存序通过零散函数名表达**：fast 与 after-arm 已经不同，但尚未形成统一的 predicate 词汇和审查规则。
3. **notify 的调用面很宽**：正确调用点横跨 opts/state/init/sync，新增状态变更时容易漏掉。
4. **RX/TX 看似对称，事实来源却不同**：过度泛化成 callback 状态机会隐藏 shared cached-min 和回收逻辑。
5. **旧文档混入未来方案**：blocking、epoll、broker、io_uring 和历史实验放在一起，不适合作为当前 futex 实现的入门材料。

## 11. 方案比较

### 方案 A：只改名、加注释，不调整文件职责

优点是改动最小、回归风险最低；缺点是 notify 调用面和 predicate/等待耦合仍然分散；风险是下一次功能变更仍可能重新把协议打散。

### 方案 B：保留算法，分离 predicate、wait-word primitive 和等待策略

优点是每层都能单独描述和测试，且不改变共享布局和外部行为；缺点是需要小步移动内部符号；风险是机械搬移时可能遗漏 publisher 或改变内存序，必须逐提交验证。

### 方案 C：换成 waiter count、sequence counter 或 eventfd/broker

优点是可能提供新的观测或集成能力；缺点是状态机、ABI、故障恢复和性能模型都要重做；风险是在当前协议尚未讲清楚前同时引入正确性和迁移问题。

**选择方案 B。** 它是能明显改善结构、同时保持当前正确性证明和行为边界的最小方案。方案 A 可作为第一小步，但不是最终结构；方案 C 留给独立 ADR 和独立验证周期。

## 12. 目标结构

重构后仍保留显式 RX/TX 循环，不引入隐藏控制流的通用 callback 框架。

### 12.1 Predicate 层

职责：只回答“现在是否满足条件”，并明确读取发生在哪个阶段。

建议保留四个意图明确的内部入口：

```c
size_t __ufifo_rx_data_len_fast(...);
size_t __ufifo_rx_data_len_after_arm(...);
size_t __ufifo_tx_available_fast(...);
size_t __ufifo_tx_available_after_arm(...);
```

- `fast` 允许使用 acquire，服务于不睡眠的热路径；
- `after_arm` 必须使用协议要求的 SC 读取；
- RX 保留记录长度；`for_wait` 保留等待循环首次检查的 SC；shared 刷新/回收仍属于策略层；
- 函数名直接暴露阶段，避免调用者随意复用弱版本。

### 12.2 Wait-word primitive 层

职责：只操作 epoch 和 futex，不理解 FIFO 数据：

- arm 并返回 expected epoch；
- 按 expected epoch futex wait；
- publish 后执行 notify 握手；
- 把 errno 归一化为清晰的内部结果。

这层不得读取 `in`、`out`、slot 或 cached minimum。

### 12.3 RX/TX policy 层

职责：显式编排：

```text
检查 -> 必要的刷新/回收 -> arm -> 强重查 -> 解锁等待 -> 重加锁 -> 循环
```

RX 和 TX 分开实现。共享代码只限 deadline、锁交接和 futex primitive，不用函数指针或多参数 callback 把关键顺序藏起来。

### 12.4 Operation/publisher 层

`ufifo_put/get/reset/skip/seek/open/close` 负责业务状态改变。每个改变都必须能在代码审查中回答：

1. 哪个谓词可能从 false 变 true？
2. 状态用什么内存序发布？
3. 对应 notify 是否在 publish 之后？

当前 get/skip/seek 共用 `__ufifo_notify_after_consume()`；其他 publisher 显式调用 RX/TX notify，数据更新与通知顺序保持可见。

## 13. 必须保持的不变量

| ID | 不变量 |
| --- | --- |
| W1 | `in/out/cached_min_out` 是谓词事实；wait word 只用于通知 |
| W2 | waiter 必须先 arm，再用 SC 重新检查谓词 |
| W3 | publisher 必须先发布谓词，再执行 notify |
| W4 | notify 保留 SC fence 与 SC wait-word observation |
| W5 | futex wait 使用 arm 返回的精确 epoch 作为 expected value |
| W6 | 所有正常 wake、EAGAIN 和虚假返回都回到谓词循环 |
| W7 | 一个公开超时操作只使用一个绝对 deadline |
| W8 | shared TX 只有有效最小 `out` 前移才表示全局空间增加 |
| W9 | reset、close、回收和 owner-death 恢复必须纳入 publisher 审计 |
| W10 | LOCK_NONE 与有锁模式使用同一等待正确性协议 |
| W11 | 进程死亡本身不被描述为可靠 wake 事件 |
| W12 | 快路径可以较弱，但一旦 arm，不能调用 fast predicate 代替强重查 |

## 14. 小步重构计划

### Phase 0：文档和基线

合入本文并冻结 W1-W12；记录 targeted/full test、sanitizer 和 benchmark 基线；不移动代码、不改内存序。

### Phase 1：统一 predicate 命名

为 RX/TX 建立 fast/after-arm 明确入口；先保留回归测试确认 armed waiter 使用强重查；只做机械替换，不同时优化性能。

### Phase 2：隔离 wait-word primitive

把 arm、futex wait、notify 组织成不接触 FIFO 数据的低层区域或独立文件；保持布局、epoch 算法和 errno 行为不变；补充奇偶转换、EAGAIN、timeout、EINTR 测试。

### Phase 3：收敛 RX/TX 等待策略

保持两个显式循环；只抽出“解锁等待并按同一 deadline 重加锁”；明确 shared refresh/reap 所属位置；每次移动后重复并发回归测试。

### Phase 4：审计所有 publisher

按 opts/state/init/sync 建立 publisher 清单；补充 reset、close/unregister、dead-reader reap、owner-death 测试；清单和测试齐全后再移动 notify。

### Phase 5：性能实验，独立于正确性重构

比较 syscall、arm、notify 次数及吞吐和尾延迟；优先优化无 waiter 时的通知成本和不必要扫描；不默认删除 fence 或弱化 after-arm load；算法变化另写 ADR 并重做证明。

## 15. 测试与验证标准

### 15.1 功能和回归

至少覆盖：非阻塞 put/get 的 success 和错误路径；blocking/timed RX/TX；arm 后谓词已成立；`EAGAIN`、虚假 wake、`EINTR`、timeout；初次加锁和 wake 后重加锁计入 timeout；sole/shared 和三种 lock；reset 和所有 TX publisher；robust owner-death 恢复。producer role 的权限测试随 role 独立提交。

并发测试必须有有界 deadline，并保证失败路径仍能 join/reap，不能用测试本身的永久挂起来证明“没有 lost-wakeup”。

### 15.2 Sanitizer 与平台证据

证据分层：ASan/UBSan 检查内存和未定义行为；TSan 提供数据竞争线索，但若提示不支持 `atomic_thread_fence`，clean run 不能证明 fence 协议；x86_64 提供主要功能和性能基线；AArch64 交叉编译/反汇编检查代码生成；QEMU 只算功能证据；真实弱内存机器的长时间压力是发布前重要证据。

### 15.3 性能与正确性分开报告

每次结论分成两栏：

- 正确性：哪些不变量、测试和平台证据已覆盖；
- 性能：具体场景、消息大小、线程/进程拓扑、吞吐/延迟和相对基线。

不能因为 benchmark 回升就声称协议正确，也不能因为测试通过就忽略明显性能回退。

## 16. 推荐阅读顺序

第一次阅读当前代码时，按以下顺序最容易建立模型：

1. `inc/ufifo_layout.h`、`inc/utils.h`、`inc/kfifo.h`：布局、原子操作和数据发布；
2. `inc/ufifo_predicate.h`、`src/ufifo_wait_word.c`、`src/ufifo_wait.c`：谓词、primitive、RX/TX 循环；
3. `src/ufifo_opts.c`：put/get 的等待、发布和通知；
4. `src/ufifo_state.c`、`src/ufifo_init.c`、`src/ufifo_sync.c`：其他 publisher；
5. wait/timeout regression tests：外部可观察语义。

阅读时始终画出同一条链：

```text
谁改变谓词？ -> 怎样 publish？ -> 谁检查？ -> 怎样 arm？
-> arm 后怎样 recheck？ -> 谁 notify？ -> futex 返回后回到哪里？
```

## 17. 改动审查清单

任何涉及等待、原子位置或生命周期的 PR，都必须回答：

- [ ] 改动影响 RX、TX，还是两者？
- [ ] 谓词事实来源是否改变？
- [ ] fast path 与 after-arm path 是否仍明确分开？
- [ ] 是否弱化了 A/R/P/F/N 中任一步的内存序？
- [ ] 是否新增了可能让谓词从 false 变 true 的 publisher？
- [ ] 所有 publisher 是否在状态发布之后 notify？
- [ ] `FUTEX_WAIT` expected epoch 是否仍来自本次 arm？
- [ ] timeout 是否仍覆盖整个操作并复用同一 deadline？
- [ ] LOCK_NONE、sole/shared、thread/process 是否都被考虑？
- [ ] 失败测试是否有界并可靠清理线程/子进程？
- [ ] 正确性证据和 benchmark 结果是否分开陈述？

## 18. 与已有文档的关系

`ufifo-v2-blocking-epoll-design.md` 保留历史方案和 epoll/io_uring 方向；`ufifo-v2-blocking-epoll-validation.md` 保留实验记录；`ufifo-v2-single-shm-lifetime.md` 定义生命周期边界；本文只解释当前 futex 协议。

如果本文与历史提案在“当前实现是什么”上冲突，以当前源码和本文列出的 W1-W12 为审查起点；历史提案中的未来能力不应被误认为已经实现。
