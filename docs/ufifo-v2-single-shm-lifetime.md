# ufifo v2 单共享内存与 Lifetime 设计

- 状态：Accepted
- 日期：2026-09-18
- 决策范围：core 共享映射、open/attach/close/destroy/force 生命周期
- 依赖：[ufifo v2 Blocking 与 Epoll 重构设计](ufifo-v2-blocking-epoll-design.md)

## 1. Problem 1-Pager

### Context

当前一个 FIFO 使用两个独立 POSIX shm 对象：

- `name` 保存数据环；
- `name_ctrl` 保存版本、锁、用户槽、索引和 wait word。

attach 分别按名字打开两者，因此 unlink/recreate、失败回滚或跨版本迁移时，
可能把不同代的 control 与 data 拼接到同一个 handle。两个 fd、两个 mmap 和两次
unlink 也使“对象仍被谁持有”无法由一个内核对象表达。

### Problem

需要同时消除三类 lifetime 空洞：

1. control 与 data 可独立创建、替换或遗留；
2. attach 在打开名字后、完成映射前可能跨过 force/destroy；
3. 旧 handle 在同名新对象创建后执行 destroy，可能误删新对象。

仅把两段内容放进同一个文件还不够；必须让打开、初始化、使用、销毁和强制重建
都服从同一个内核可仲裁的生命周期协议。

### Goal

1. 一个 FIFO 只有一个 POSIX shm inode、一个 handle fd 和一个连续 mmap。
2. control、用户槽和 data 的偏移、大小均属于共享 ABI，并在 attach 时完整校验。
3. 每个成功 open 的 handle 在整个生命周期持有 shared OFD lifetime lock。
4. destroy/force 必须先取得 exclusive lifetime lock；有其他活跃 handle 时返回
   `-EBUSY`，不修改名字或现有对象。
5. attach 取得 shared lock 后复核名字仍指向同一个 inode；若已换代则返回
   `-EAGAIN`，绝不 attach 到已被替换的匿名旧对象。

### Non-Goals

- 不让 v2 与旧双-shm handle 同时操作同一 FIFO。
- 不恢复 broker、eventfd 或旧 epoll API。
- 不改变 FIFO 数据分发、record hook 或 futex wait-word 语义。
- 不让 `ufifo_destroy()` 等待其他 handle 退出；忙时立即返回 `-EBUSY`。
- 不提供跨主机、持久化或崩溃后保留数据的保证。
- 不兼容、探测或清理旧双-shm 布局，也不处理遗留 broker；attach 对非 ABI 3 对象返回 `-EPROTO`。
- fork 继承的同一 open file description 不计作独立 lifetime lease；继承 handle 的 API 返回
  `-ECHILD` 并设置 `errno=ECHILD`，child 必须重新 attach。

### Constraints

- Linux OFD locks；不增加第二个锁文件、named semaphore 或守护进程。
- file ≤ 500 LOC，function ≤ 80 LOC，parameters ≤ 5，复杂度 ≤ 10。
- 所有 size/offset 加法、乘法和对齐先检查溢出。
- attach 在使用共享字段计算地址前校验固定头、枚举、数量和文件边界。

## 2. 方案比较

| 方案 | 优点 | 缺点/风险 | 结论 |
| --- | --- | --- | --- |
| 单 shm、control/data 两次 mmap | 接近现有 handle 结构 | 仍有两套映射范围和回滚路径；data offset 必须页对齐 | 拒绝 |
| 单 shm、单次连续 mmap | 一个 fd/mapping/inode；最容易证明所有权 | 共享布局和 init 路径一次性重做 | 采用 |
| 单 shm + 共享引用计数 | 可尝试 last-close unlink | 崩溃泄漏计数；attach 与 last-close 仍有竞态 | 拒绝 |
| 单 shm + 全生命周期 OFD lock | 进程崩溃自动释放；内核仲裁 live handle | 需要定义 lock byte 和 inode 复核 | 采用 |

## 3. 单对象布局

```text
offset 0
+------------------------------+
| ufifo_ctrl_t fixed header    |
+------------------------------+
| users[max_users + 1]         |
+------------------------------+
| alignment padding (64-byte)  |
+------------------------------+ <- data_offset
| ring data[data_size]         |
+------------------------------+ <- mapping_size / file size
```

控制头包含单映射边界：

```c
uint32_t layout_abi;
size_t mapping_size;
size_t data_offset;
size_t data_size;
```

规则：

- `slot_count = max_users + 1`；额外槽继续供 SOLE 全局 RX 状态使用；
- `max_users >= 1`；不再有 broker 派生的固定用户数上限，实际边界由 `size_t`、布局
  溢出检查、`off_t` 文件大小和系统资源共同决定；
- `data_offset = align_up(sizeof(ufifo_ctrl_t) + slot_count * sizeof(ufifo_sub_ctrl_t), 64)`；
- `data_size` 是不小于请求值的 2 次幂，最小为 2；
- `mapping_size = data_offset + data_size`，并且等于 shm 文件大小；
- `mask + 1 == data_size`；
- `handle->ctrl` 指向映射起点，`handle->shm_mem` 指向 `base + data_offset`。

共享布局 ABI 当前为 3；attach 通过 `layout_abi` 明确拒绝不兼容对象。初始化完成性
由 lifetime OFD lock 仲裁，不在共享布局中维护额外状态机。

## 4. OFD Lock 分配

同一个 shm fd 的 byte-range lock 分配如下：

```text
byte 0: lifetime / initialization lock
byte 1 + user_id: user liveness lock
```

### 4.1 Lifetime lock

- 新 ALLOC：以 exclusive lock 初始化；完成后原地降级为 shared lock并保留。
- ATTACH：非阻塞获取 shared lock；与初始化冲突时返回 `-EAGAIN`，成功后在 handle close 前保留。
- DESTROY：把本 handle 的 shared lock非阻塞升级为 exclusive；失败返回 `-EBUSY`。
- FORCE：临时打开当前名字并非阻塞获取 exclusive；失败返回 `-EBUSY`。
- 进程崩溃或最后一个 fd close 时，内核自动释放对应 OFD lock。

### 4.2 User liveness lock

用户槽锁从旧的 `user_id` 平移到 `1 + user_id`，避免 user 0 与 lifetime byte 冲突。
它继续用于 dead-reader 检测和槽回收。

## 5. Attach Identity Revalidation

attach 的顺序固定为：

1. `shm_open(name)` 得到 candidate fd；
2. 在 candidate byte 0 非阻塞获取 shared lifetime lock；冲突时返回 `-EAGAIN`；
3. 再次 `shm_open(name)` 得到 current fd；
4. 分别 `fstat()`，比较 `st_dev` 与 `st_ino`；
5. 相同则关闭 current fd并继续；不同或名字暂时不存在则关闭 candidate 并返回
   `-EAGAIN`。

新对象在 `shm_open(O_EXCL)` 与取得 exclusive lock 之间存在极短的名字发布窗口。
creator 在 `shm_open(O_EXCL)` 返回后立即请求 exclusive lock，把窗口压缩到最小。
attach 若初次打开时名字不存在则立即返回 `-ENOENT`；若已打开的对象尚小于固定头，
或 identity revalidation 发现换代，则释放 shared lock并返回 `-EAGAIN`。core 不内置
重试次数和延迟，调用方自行决定重试策略。

因此 force/destroy 可以在步骤 1 与步骤 2 之间替换名字，但 attach 不会把旧 inode
作为成功 handle 返回。一旦步骤 4 通过，shared lock 会阻止该 inode 被合法 force 或
destroy，直到 handle close。

## 6. Destroy 与 Force 契约

### 6.1 Destroy

`ufifo_destroy(handle)`：

1. 非阻塞升级 lifetime lock；
2. `EAGAIN`/`EACCES` 转为 `-EBUSY`，handle 保持完全有效；
3. 成功后 unregister 当前用户、销毁 mutex、unlink 单一名字；
4. unmap、close、释放 handle。

exclusive lock 证明不存在其他遵守当前协议的活跃 handle，因此不会在其他进程仍使用
共享 mutex/futex 时销毁它们。

### 6.2 Force

`ALLOC + force=1`：

1. 若名字不存在，直接创建；
2. 只有取得 exclusive lifetime lock 才能 unlink；否则 `-EBUSY`；
3. force 表示调用方拥有该名字，因此不探测对象布局，直接 unlink 当前对象；
4. 创建 ABI 3 单对象；
5. 全程不在遵守 lifetime lock 的活跃 handle 存在时创建同名新代对象。

## 7. 状态与错误

```text
ALLOC new:  create -> EXCLUSIVE(init) -> map/init -> SHARED(live)
ATTACH:     open -> SHARED(wait init) -> identity check -> map/validate -> live
DESTROY:    SHARED -> try EXCLUSIVE -> unlink/free
                                `-> -EBUSY, handle unchanged
FORCE:      open old -> try EXCLUSIVE -> unlink -> create/init new
                                `-> -EBUSY, old object unchanged
```

错误规则：

- 活跃 handle 阻止 destroy/force：`-EBUSY`；
- 固定头、layout ABI、offset/size 或文件长度不合法：`-EPROTO`；
- 初次 attach 时名字不存在：`-ENOENT`；
- 对象尚未初始化或同名对象在 attach 期间换代：`-EAGAIN`；
- 初始化失败：在 exclusive lock 下 unlink 未完成对象，close 自动释放锁。
- fork 子进程使用继承 handle：`-ECHILD`；
- robust data mutex owner death：下一个 locker 清空不确定数据、恢复 mutex 并返回
  `-EOWNERDEAD`；后续操作正常继续。

## 8. 验证矩阵

- 单一名字存在，`name_ctrl` 不存在；每 handle 只有一个 shm fd 和一个 mmap。
- ALLOC/ATTACH 的 ctrl 与 data 位于同一 inode、同一映射边界内。
- active attach 存在时 destroy 返回 `-EBUSY`，原 handle 继续可读写。
- active handle 存在时 force 返回 `-EBUSY`，名字和数据不变。
- 最后一个其他 handle close 后 destroy/force 成功。
- attach 与 force 并发时只得到旧代、新代完整对象或显式瞬态错误，不出现 mixed generation。
- owner/attacher SIGKILL 后 lifetime lock 自动释放，可 force/reap。
- 伪造/截断的 mapping size、data offset、data size、max_users，以及由 `max_users + 1`
  导致的布局溢出全部返回 `-EPROTO`。
- 非 ABI 3 对象的 attach 返回 `-EPROTO`；force 不探测 layout，直接替换无活跃 lease 的对象。
- creator 在任意初始化阶段死亡后，force 可以在取得 exclusive lock 后回收残留名字。
- fork child 的继承 handle 返回 `-ECHILD`，不会注销 parent slot 或解除 parent OFD lock。
- data mutex owner death 由下一个 locker 检测；该调用返回 `-EOWNERDEAD`，后续读写正常。
- futex、SOLE/SHARED、record/tag 通过全量 CTest；单 SHM lifetime/layout 通过
  ASan+UBSan 与 TSan 聚焦回归。

## 9. 影响说明

- `inc/ufifo_layout.h`：布局 ABI 3，保存单映射边界，不增加初始化或数据健康状态机。
- `inc/ufifo_internal.h`：删除 `ctrl_fd/ctrl_size`，增加 `mapping_size`。
- `src/ufifo_sync.c`：lifetime lock 与平移后的 user liveness lock。
- `src/ufifo_init.c`：按 create/attach/map/validate/destroy 职责拆分。
- `src/ufifo_info.c`：只报告一个 shm fd/mapping。
- `inc/ufifo.h`：删除历史 broker 用户数上限；`max_users` 仍是每个 FIFO 的实际容量。
- 测试不再创建或清理 `_ctrl`。

## 10. 本阶段验证证据

- 返回约定统一后，常规构建与全量 CTest：421/421 通过，48 个既有参数组合跳过；
  ASan+UBSan 聚焦接口与 fork guard 用例：9/9 通过（`detect_leaks=0`）。
- 简化后的 P0 常规构建与全量 CTest：420/420 通过，48 个既有参数组合跳过。
- fork guard、ctrl recovery、owner-death reset、force 和 attach/force race 共 7 个聚焦用例
  通过 ASan+UBSan（`detect_leaks=0`；当前 ptrace 环境不支持 LeakSanitizer）。
- 常规构建与全量 CTest：416/416 通过，48 个既有参数组合跳过。
- ASan（关闭 ptrace 环境下不可用的 LeakSanitizer）：416/416 通过，48 个既有参数组合跳过。
- ASan、ASan+UBSan、TSan 聚焦 lifetime/layout 与 attach 错误契约：各 13/13 通过；
  attach/force 竞态额外重复 1000 次通过。
- 此前 ASan+UBSan 全量为 407/413，其余 6 个失败均来自既有可变长记录回调对非对齐
  结构体的解引用，与单 SHM lifetime 路径无关，本提交不顺带修改。
