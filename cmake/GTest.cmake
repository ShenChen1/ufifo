# GTest support
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# ufifo test executable
add_executable(ufifo_test test/ufifo_test.cpp)
target_link_libraries(ufifo_test PRIVATE
    ufifo_static
    ${RT_LIBRARY}
    ${PTHREAD_LIBRARY}
    GTest::gtest_main
)
target_include_directories(ufifo_test PRIVATE ${CMAKE_SOURCE_DIR}/inc)
target_compile_options(ufifo_test PRIVATE -g -O0 -Wall -Werror -Wno-error=maybe-uninitialized)
if(COVERAGE)
    ufifo_enable_coverage(ufifo_test)
endif()

include(GoogleTest)
gtest_discover_tests(ufifo_test)

# Performance benchmark executable (compiled with -Os for realistic measurement)
add_executable(ufifo_bench test/ufifo_bench.cpp)
target_link_libraries(ufifo_bench PRIVATE
    ufifo_static
    ${RT_LIBRARY}
    ${PTHREAD_LIBRARY}
)
target_include_directories(ufifo_bench PRIVATE ${CMAKE_SOURCE_DIR}/inc)
target_compile_options(ufifo_bench PRIVATE -g -Os -Wall -Werror)