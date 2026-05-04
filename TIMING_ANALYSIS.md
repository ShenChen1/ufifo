# `ufifo` 时序与内存屏障分析报告

本文档针对 `ufifo` 库中各种无锁/极简锁机制下的 C11 内存屏障（`smp_load_acquire`、`smp_store_release`、`READ_ONCE`、`WRITE_ONCE`）进行场景化的时序分析，评估当前实现是否存在潜在的深层次 Bug。

## 场景一：数据面（Data Path）与 Ring-buffer (`kfifo.in` / `kfifo.out`)

`kfifo.in` 和 `kfifo.out` 是整个 ring-buffer 运转的核心变量。

### 1. 单一写入者，单一读取者（经典 kfifo）

在 `__ufifo_put` 中：
```c
unsigned int in = READ_ONCE(handle->kfifo.in);
// ... write data to shared memory ...
smp_store_release(handle->kfifo.in, in + len);
```

在 `__ufifo_get` 中（通过 `kfifo_out`）：
```c
unsigned int in = smp_load_acquire(fifo->in);
unsigned int out = READ_ONCE(fifo->out);
// ... read data from shared memory ...
smp_store_release(fifo->out, out + len);
```

**时序分析**：
- **生产者（put）**：`smp_store_release` 确保共享内存中数据的写入必须在 `kfifo.in` 的更新对外可见之前完成。这是绝对正确的 release 语义。
- **消费者（get/peek）**：`smp_load_acquire(fifo->in)` 确保消费者读取到了最新的 `in` 值后，由于 acquire 语义，后续读取实际数据的操作（`memcpy` 或者 `hook.recget`）绝对不会被 CPU/编译器重排到读取 `in` 之前。
- **结论**：这一层面的基础 C11 barrier 搭配非常标准，保证了数据内容的正确可见性，没有内存序问题。

---

## 场景二：多消费者广播模式 (`SHARED` 模式)

在 `SHARED` 模式下，有单一的生产者和 N 个独立的消费者（Fan-out）。为了计算剩余空间，生产者需要知道所有活跃消费者的最慢进度（`cached_min_out`）。

### 1. `users[i].active` 和 `users[i].out`

**活跃度标记：**
在 `ufifo_init.c`（注册用户）中：
```c
WRITE_ONCE(&ctrl->users[i].out, READ_ONCE(&ctrl->in));
smp_store_release(&ctrl->users[i].active, 1);
```
在清理死用户时（`__ufifo_reap_dead_user`）：
```c
WRITE_ONCE(&ctrl->users[user_id].active, 0);
```

**更新进度：**
消费者在获取数据后更新自己的 `out`，并可能会更新全局的缓存：
```c
smp_store_release(&handle->ctrl->users[user_id].out, out + len);
```

**生产者获取最小进度 (`__ufifo_min_out`)**：
```c
for (i = 0; i < handle->ctrl->max_users; i++) {
    if (smp_load_acquire(&handle->ctrl->users[i].active)) {
        unsigned int u_out = smp_load_acquire(&handle->ctrl->users[i].out);
        // ...
    }
}
```

**深层次 Bug 分析（ABA/时序窗口）**：
考虑以下时序：
1. 生产者执行 `__ufifo_min_out`，检查 `users[i].active` 发现为 1（acquire）。
2. **发生抢占**：此消费者 `i` 突然崩溃。
3. 其他进程（例如触发了清理逻辑）调用 `__ufifo_reap_dead_user`，将 `users[i].active` 设置为 0 (`WRITE_ONCE`)。
4. 一个新的进程快速启动，复用了槽位 `i`，设置新的 `users[i].out` (等于当前最新的 `in`)，并且将 `users[i].active` 置 1 (`smp_store_release`)。
5. 生产者恢复执行，读取 `users[i].out` (`smp_load_acquire`)。此时它读到了 **新进程** 的 `out`（通常较大）。
由于 `ufifo` 是在计算所有有效 `out` 的最小值，并且 `out` 在正常情况下是单调递增的（带绕回处理）。新进程的 `out` 会被初始化为 `in`（最大值）。如果生产者读到了新的 `out`，它只可能高估可用空间，在旧消费者实际上由于崩溃而不再消费的前提下，这在逻辑上恰恰是我们期望的（回收空间）。如果读到的是旧消费者的残留 `out`，也只会导致当前这一轮少计算了空间。
因此，虽然 `active` 和 `out` 的读取之间有短暂窗口，但基于此业务逻辑（求极小值，以及新注册 `out=in`），不会导致严重的内存破坏或数据丢失。

### 2. `cached_min_out` 更新逻辑

```c
void __ufifo_update_cached_min_out(ufifo_t *handle)
{
    unsigned int min_o = __ufifo_min_out(handle);
    unsigned int cur_cached = smp_load_acquire(&handle->ctrl->cached_min_out);

    while ((int)(min_o - cur_cached) > 0) {
        if (atomic_cmpxchg(&handle->ctrl->cached_min_out, &cur_cached, min_o)) {
            break;
        }
    }
}
```

**时序分析**：
这里的 `atomic_cmpxchg` 带有 `__ATOMIC_ACQ_REL` (在 `utils.h` 中的定义)。多个消费者（甚至生产者）并发更新 `cached_min_out` 时，仅当计算出的新最小值严格大于当前缓存值时才更新，确保 `cached_min_out` 单调推进。这对于保证安全十分完美。

---

## 场景三：初始化同步 (`init_done`)

在 `ALLOC` 时：
```c
WRITE_ONCE(&handle->ctrl->init_done, 0);
// 初始化共享内存数据...
smp_store_release(&handle->ctrl->init_done, 1);
```

在 `ATTACH` 附加时：
```c
if (!smp_load_acquire(&handle->ctrl->init_done)) {
    ret = -EIO;
}
```

**时序分析**：
由于底层还有 `__ufifo_init_lock(fd)` / `__ufifo_init_wait(fd)` 作为内核级文件锁（OFD）来阻塞 `ATTACH` 直到 `ALLOC` 完成。`init_done` 更像是一个内存可见性的最后一道屏障和状态校验。`smp_store_release` 和 `smp_load_acquire` 确保 `ATTACH` 进程在看到 `init_done == 1` 时，必然能看到 `ALLOC` 进程写入的所有数据。这是安全且正确的。

---

## 场景四：Epoll 唤醒机制 (`epoll_armed` 与通知)

这是 `ufifo` 为了避免过度系统调用（Syscall Storm）引入的核心机制：

**消费者想要读取数据 (epoll RX 监听) / 生产者想要写入 (TX 监听) `ufifo_epoll.c`**：
```c
int ufifo_get_rx_fd(ufifo_t *handle)
{
    // ...
    if (smp_load_acquire(handle->kfifo.in) != READ_ONCE(handle->kfifo.out)) {
        __ufifo_efd_post(handle->efd_rd);
    } else {
        smp_store_release(&handle->ctrl->users[idx].epoll_armed, 1);
    }
    // ...
}
```

**生产者在放数据后唤醒消费者 (`__ufifo_efd_notify`)**：
```c
int __ufifo_efd_notify(int efd, int *waiters, int *epoll_armed)
{
    int ret = 0;
    int w = smp_load_acquire(waiters);
    int armed = smp_load_acquire(epoll_armed);

    if (w > 0 || armed > 0) {
        armed = atomic_xchg(epoll_armed, 0);
        uint64_t post_count = (w > 0 ? w : 0) + armed;
        if (post_count > 0) {
            ret = write(efd, &post_count, sizeof(post_count));
        }
    }
    return ret < 0 ? -errno : 0;
}
```

**潜在的深层 Bug 时序（Lost Wakeup 丢失唤醒风险分析）**：
我们来构建一个极限并发时序：

假设 `kfifo` 此时为空。
**消费者：** 正在调用 `ufifo_get_rx_fd` 或 `ufifo_drain_rx_fd`。
**生产者：** 正在调用 `__ufifo_put` 并准备执行 `__ufifo_efd_notify`。

1. **消费者**：检查 `smp_load_acquire(in) != READ_ONCE(out)`，发现为空 (in == out)。
2. **生产者**：执行 `smp_store_release(kfifo.in, in + len)` 写入了数据！
3. **生产者**：进入 `__ufifo_efd_notify`，执行 `armed = smp_load_acquire(epoll_armed)`。因为此时消费者还没来得及设 1，生产者读到了 `armed == 0`（假设此时没有阻塞在 `poll` 的线程，即 `waiters == 0`）。
4. **生产者**：判断 `if (w > 0 || armed > 0)` 不成立，直接返回！不触发 `eventfd_write`。
5. **消费者**：继续它的流程，执行 `smp_store_release(epoll_armed, 1)`。
6. **最终状态**：队列里有数据，消费者进入了 `epoll_wait` 挂起（`epoll_armed` 是 1），但生产者已经错过了唤醒消费者的时机。这就造成了 **Lost Wakeup（唤醒丢失）**！

### 结论与修复建议

上述丢失唤醒（Lost Wakeup）是当前代码库中存在的一个非常典型且致命的无锁并发时序漏洞。
在经典的双检查（Double-check）或无锁事件通知模式中，如果采用先检查状态再挂入等待队列的模式，**必须**在挂入等待队列（设 `epoll_armed=1`）之后，**再次**检查状态（数据是否到达）。

当前 `ufifo_get_rx_fd` 和 `ufifo_drain_rx_fd` 的逻辑中：
```c
int ufifo_drain_rx_fd(ufifo_t *handle)
{
    // ...
    int ret = __ufifo_efd_drain(handle->efd_rd);
    smp_store_release(&handle->ctrl->users[idx].epoll_armed, 1); /* re-arm */
    // --> 在这里，如果没有再次检查 in != out 并可能补发信号，就存在丢失唤醒风险。
    return ret;
}
```
**修复方案思路**：在设置 `epoll_armed = 1` 之后，必须增加一次全内存屏障（或者通过 atomic 交换），然后再去检查一次 `kfifo.in`（RX情况）或可用空间（TX情况）。如果检查发现有数据/空间，需要主动尝试把 `epoll_armed` 重置回 0，并主动写一次 `eventfd` 以防止消费者陷入永久沉睡。

---

## 总结

1. **常规读写面与 `cached_min_out` 缓存逻辑**：使用的 `smp_load_acquire` 和 `smp_store_release` 极度精准，无重排隐患，ABA 问题也在容错区间内。
2. **潜在 Deep Bug 警告**：`epoll_armed` / `epoll_tx_armed` 的通知机制存在经典的数据竞态时序漏洞。在 `ufifo_get_rx_fd` / `ufifo_get_tx_fd` 以及它们的 `drain` 方法中，仅仅执行 `smp_store_release(armed, 1)` 是不够的。缺乏设 1 后的 **"二次查验"** 机制，当生产者和消费者的操作微秒级交叉时，极有可能导致唤醒丢失。