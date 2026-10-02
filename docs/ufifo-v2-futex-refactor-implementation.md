# futex 结构重构落地记录

日期：2026-10-02。设计与 W1–W12 见 `ufifo-v2-futex-wait-refactor.md`。

## Problem 1-Pager

- Context：HEAD 已有 C11 fence 握手；工作区另有 role、原子表示替换和测试归并。
- Problem：谓词、cached-min 维护、syscall、等待策略和数据操作混在一起，难以核对发布和唤醒。
- Goal：保持现有行为，将各层职责与锁交接写成直接可读、可单独测试的实现。
- Non-Goals：不改变 API、布局、权限、reset、原子表示、内存序或通知算法；不优化性能。
- Constraints：保留 W1–W12、绝对 deadline、errno、data-lock ownership；不修改其他未提交内容。

## 方案与决定

- 仅改名：搬移风险低，但 syscall 和策略仍混杂，后续维护收益有限。
- 保持协议并分层：职责清晰且可测试；风险是搬移时遗漏发布点或改变顺序。

选择第二项；保留显式 RX/TX 循环，不引入 callback 状态机。纯谓词采用内部 inline header。

## 提交边界

本次只提交纯结构重构、设计文档及不依赖 role 的谓词/协议测试。
role、GCC 原子表示替换、kfifo/TX 快路径内存序优化、TSan 警告配置、测试目录归并均留在工作区。
假设：以 HEAD 的行为作为独立提交基线，而不是把整个开发工作区当作已合入版本。
因此 TX fast 和 after-arm 都保留 SC；RX fast 为 acquire，等待循环和 after-arm 为 SC。

## 模块与影响

| 文件 | 职责 |
| --- | --- |
| `inc/ufifo_predicate.h` | 只读 RX/TX fast、for-wait、after-arm 谓词及固定快照记录长度 |
| `inc/ufifo_wait_word.h` / `src/ufifo_wait_word.c` | SC arm、epoch、futex wait、notify；不接触数据位置 |
| `src/ufifo_capacity.c` | shared 最小消费位置扫描、cached-min 单调更新 |
| `src/ufifo_wait.c` | RX/TX 循环、shared 刷新/回收及解锁等待和重加锁 |
| `src/ufifo_opts.c` / `src/ufifo_state.c` | 数据操作、release 发布和显式通知 |
| `inc/ufifo_internal.h` | get/skip/seek 的共同消费通知判断 |

影响说明：旧 unused-length/peek-data-length 内部符号由阶段明确的谓词替代；
get/skip/seek 共享消费通知，操作退出共用持锁状态检查；公开行为和其他 publisher 位置不变。

## 锁交接退出契约

| 分支 | `data_lock_held` | 退出动作 |
| --- | --- | --- |
| arm 后谓词已满足 | true | 不解锁、不等待，继续操作 |
| futex 错误，重拿锁成功 | true | 返回 futex 错误，由操作层解锁 |
| 重拿锁失败 | false | 加锁错误优先，不继续操作、不二次解锁 |
| 交出锁失败 | false | 返回解锁错误，不等待、不再尝试解锁 |

最后一行是保守的清理权限标记，不代表物理 mutex 已释放；正常调用须满足持锁前置条件。

## 测试边界与验证

- 10 项谓词用例覆盖 sole/shared、空满、记录长度及 ENOBUFS、索引回绕、只读 cached-min。
- 84 项脚本用例覆盖 14 种边界事件 × RX/sole TX/shared TX × blocking/timed。
- 脚本核对 arm 返回的 expected epoch、同一 deadline、虚假返回重试、错误优先级和锁清理。
- `--wrap` 替身仅在独立可执行文件中；生产库不增加 hook，arm 和谓词仍是真实实现。
- 真实 futex、进程共享、robust mutex 和 publisher 路径继续由 HEAD 的既有集成测试覆盖。

纯提交版本在独立临时目录构建：Release 全量 CTest 553 项，507 通过、46 按契约跳过、0 失败。
ASan/UBSan 构建与同样的 553 项全量测试通过，46 跳过、0 失败；配置使用 `-DSANITIZER=asan,ubsan`。
发现和运行测试时设置 `ASAN_OPTIONS=detect_leaks=0`；运行时另设 `UBSAN_OPTIONS=halt_on_error=1`。
复现：`cmake -S . -B build -DCMAKE_BUILD_TYPE=Release`，然后构建并运行 `ctest --test-dir build --output-on-failure --timeout 30`。
此前整个开发工作区的测试和 benchmark 不作为这个拆分提交的独立证据。
确定性替身不证明内核入队、弱内存正确性或跨进程恢复；本次不声称远端 CI 成功。
