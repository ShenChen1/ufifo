# Test layout

All GoogleTest sources are linked into `ufifo_test`; the directories describe responsibility rather than separate
execution tiers.

| Directory | Responsibility |
| --- | --- |
| `contract/` | Public API validation, errno contracts, and shared-memory layout compatibility |
| `data/` | Record/tag behavior and data-path regressions |
| `concurrency/` | Wait primitives, wake-up races, and SPSC/SPMC/MPSC/MPMC topologies |
| `lifecycle/` | Attach/destroy/reap behavior, crash recovery, and generation races |
| `support/` | Test fixtures, parameter matrices, and adapters shared by the suites |
| `benchmark/` | The standalone `ufifo_bench` performance tool; it is not registered with CTest |

Build and run the complete suite:

```sh
cmake --build build --target ufifo_test -- -j2
ctest --test-dir build --output-on-failure
```

Run a category by GoogleTest suite name when diagnosing a focused failure, for example:

```sh
./build/bin/ufifo_test --gtest_filter='UfifoWait*:*Timeout*'
```

Build and run the benchmark with its default five repetitions:

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
