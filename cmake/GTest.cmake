# GTest support
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Integration tests share one executable; boundary doubles run in an isolated executable.
set(UFIFO_CONTRACT_TEST_SOURCES
    test/contract/ufifo_api_test.cpp
    test/contract/ufifo_errno_test.cpp
    test/contract/ufifo_layout_test.cpp
    test/contract/ufifo_role_test.cpp
)
set(UFIFO_DATA_TEST_SOURCES
    test/data/ufifo_shared_data_regression_test.cpp
    test/data/ufifo_tag_test.cpp
)
set(UFIFO_WAIT_TEST_SOURCES
    test/wait/ufifo_predicate_test.cpp
    test/wait/ufifo_wait_integration_test.cpp
    test/wait/ufifo_wait_policy_test.cpp
    test/wait/ufifo_wait_word_test.cpp
)
set(UFIFO_CONCURRENCY_TEST_SOURCES
    test/concurrency/ufifo_topology_test.cpp
)
set(UFIFO_LIFECYCLE_TEST_SOURCES
    test/lifecycle/ufifo_fault_test.cpp
    test/lifecycle/ufifo_lifetime_test.cpp
    test/lifecycle/ufifo_recovery_test.cpp
)
set(UFIFO_SUPPORT_TEST_SOURCES
    test/support/ufifo_test_runtime_test.cpp
)
set(UFIFO_BENCHMARK_TEST_SOURCES
    test/benchmark/ufifo_bench_test.cpp
)

add_executable(ufifo_test
    ${UFIFO_CONTRACT_TEST_SOURCES}
    ${UFIFO_DATA_TEST_SOURCES}
    ${UFIFO_WAIT_TEST_SOURCES}
    ${UFIFO_CONCURRENCY_TEST_SOURCES}
    ${UFIFO_LIFECYCLE_TEST_SOURCES}
    ${UFIFO_SUPPORT_TEST_SOURCES}
    ${UFIFO_BENCHMARK_TEST_SOURCES}
    test/support/ufifo_test_runtime.cpp
    test/support/ufifo_test_support.cpp
    test/benchmark/ufifo_bench_support.cpp
)
target_link_libraries(ufifo_test PRIVATE
    ufifo_static
    ${RT_LIBRARY}
    ${PTHREAD_LIBRARY}
    GTest::gtest_main
)
target_include_directories(ufifo_test PRIVATE
    ${CMAKE_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/test/support
    ${CMAKE_SOURCE_DIR}/test/benchmark
)
target_compile_options(ufifo_test PRIVATE -g -O0 -Wall -Werror -Wno-error=maybe-uninitialized)
if(COVERAGE)
    ufifo_enable_coverage(ufifo_test)
endif()

include(GoogleTest)
if(NOT CMAKE_CROSSCOMPILING OR CMAKE_CROSSCOMPILING_EMULATOR)
    gtest_discover_tests(ufifo_test PROPERTIES TIMEOUT 45)
endif()

add_executable(ufifo_wait_protocol_test test/wait/ufifo_wait_protocol_test.cpp)
target_link_libraries(ufifo_wait_protocol_test PRIVATE ufifo_static ${RT_LIBRARY} ${PTHREAD_LIBRARY} GTest::gtest_main)
target_compile_options(ufifo_wait_protocol_test PRIVATE -g -O0 -Wall -Werror)
target_link_options(ufifo_wait_protocol_test PRIVATE
    -Wl,--wrap=__ufifo_wait_arm
    -Wl,--wrap=__ufifo_futex_wait
    -Wl,--wrap=__ufifo_data_unlock
    -Wl,--wrap=__ufifo_data_lock_until
)
if(COVERAGE)
    ufifo_enable_coverage(ufifo_wait_protocol_test)
    add_dependencies(coverage ufifo_wait_protocol_test)
endif()
if(NOT CMAKE_CROSSCOMPILING OR CMAKE_CROSSCOMPILING_EMULATOR)
    gtest_discover_tests(ufifo_wait_protocol_test NO_PRETTY_VALUES PROPERTIES TIMEOUT 5)
endif()

# Performance benchmark executable (compiled with -O3 for realistic measurement)
add_executable(ufifo_bench
    test/benchmark/ufifo_bench_main.cpp
    test/benchmark/ufifo_bench_scenarios.cpp
    test/benchmark/ufifo_bench_support.cpp
)
target_link_libraries(ufifo_bench PRIVATE
    ufifo_shared
    ${RT_LIBRARY}
    ${PTHREAD_LIBRARY}
)
target_include_directories(ufifo_bench PRIVATE
    ${CMAKE_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/test/benchmark
)
target_compile_options(ufifo_bench PRIVATE -g -O3 -flto -Wall -Werror)
target_link_options(ufifo_bench PRIVATE -flto)
