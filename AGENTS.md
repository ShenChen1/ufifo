# Repository Guidelines

## Project Structure & Module Organization

`ufifo` is a GNU/Linux shared-memory FIFO library written in C99. Public and internal headers live in `inc/`; keep exported API changes in `inc/ufifo.h` and implementation details in the other headers. Core code is split by responsibility under `src/` (`ufifo_init.c`, `ufifo_sync.c`, `ufifo_epoll.c`, and related modules). Runnable usage examples are in `example/`. GoogleTest tests and performance benchmarks are in `test/`. Custom CMake helpers, cross-compilation toolchains, and Doxygen configuration live in `cmake/` and `docs/`.

## Build, Test, and Development Commands

```bash
cmake -B build
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Configuration downloads GoogleTest, builds static/shared libraries, examples, `ufifo_test`, and `ufifo_bench`. Run an example with `./build/bin/bytestream` or the benchmark with `./build/bin/ufifo_bench`.

Use separate build directories for instrumentation:

```bash
cmake -B build-asan -DSANITIZER="asan,ubsan"
cmake --build build-asan -j"$(nproc)"
ctest --test-dir build-asan --output-on-failure --timeout 300
cmake -B build-cov -DCOVERAGE=ON
cmake --build build-cov --target coverage -j"$(nproc)"
```

## Coding Style & Naming Conventions

Follow `.clang-format`: four-space indentation, no tabs, 120-column limit, sorted includes, and right-aligned pointers. Format touched C/C++ files with `clang-format -i path/to/file`. The build enables `-Wall -Werror`; new code must compile warning-free. Keep public symbols under the `ufifo_` prefix, constants as `UFIFO_*`, and file names lowercase with underscores. Preserve C compatibility in public headers; C++ is used only for tests and benchmarks.

## Testing Guidelines

Add behavior and regression coverage to `test/ufifo_test.cpp`, using descriptive GoogleTest names such as `TEST_F(UfifoApiTest, OpenWithNullName)`. Exercise relevant data formats, `SOLE`/`SHARED` modes, and lock modes when changing shared behavior. Run normal tests plus the appropriate sanitizer. For hot-path changes, run `ufifo_bench` and report meaningful throughput changes. Coverage reports are generated under `build-cov/coverage_report/`.

## Commit & Pull Request Guidelines

Recent history uses concise, imperative Conventional Commit-style subjects: `feat:`, `fix:`, `perf:`, `test:`, `docs:`, `build:`, and `refactor:`; optional scopes are accepted, for example `feat(build): ...`. Keep commits focused. Pull requests should explain behavior and API impact, list test commands and results, link relevant issues, and include benchmark data for performance-sensitive changes. Call out shared-memory layout changes explicitly because incompatible layouts require a major version change.
