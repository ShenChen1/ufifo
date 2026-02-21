cmake_minimum_required(VERSION 3.14)
project(ufifo VERSION 1.0.0 LANGUAGES C CXX)

# Options
option(SANITIZER "Enable Address Sanitizer" OFF)
option(COVERAGE "Enable code coverage with gcov/lcov" OFF)

# Compiler settings
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/inc)

# Common compile options for ufifo targets (applied per-target below)

# Sanitizer support
if(SANITIZER)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer -fno-common)
    add_link_options(-fsanitize=address)
endif()

# Find required libraries
find_library(RT_LIBRARY rt)
find_library(PTHREAD_LIBRARY pthread)

# Library source files
set(LIB_SOURCES
    src/kfifo.c
    src/ufifo.c
)

# Create static library
add_library(ufifo_static STATIC ${LIB_SOURCES})
set_target_properties(ufifo_static PROPERTIES
    OUTPUT_NAME ufifo
    POSITION_INDEPENDENT_CODE ON
)
target_compile_options(ufifo_static PRIVATE -g -Os -Wall -Werror)

# Create shared library
add_library(ufifo_shared SHARED ${LIB_SOURCES})
set_target_properties(ufifo_shared PROPERTIES
    OUTPUT_NAME ufifo
    POSITION_INDEPENDENT_CODE ON
)
target_compile_options(ufifo_shared PRIVATE -g -Os -Wall -Werror)

# Example executables
set(EXAMPLES
    bytestream
    nolock
    pressure
    record
    record-tag
    record-tag-cb
)

foreach(example ${EXAMPLES})
    add_executable(${example} example/${example}.c)
    target_compile_options(${example} PRIVATE -g -Os -Wall -Werror)
    target_link_libraries(${example} PRIVATE ufifo_static ${RT_LIBRARY} ${PTHREAD_LIBRARY})
endforeach()

# Install targets
install(FILES inc/ufifo.h
    DESTINATION ${CMAKE_INSTALL_PREFIX}/usr/local/include/ufifo/
)
install(TARGETS ufifo_shared
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/usr/local/lib/
)

# Test target
enable_testing()
foreach(example ${EXAMPLES})
    add_test(NAME ${example} COMMAND ${example})
endforeach()

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

include(GoogleTest)
gtest_discover_tests(ufifo_test)

# Coverage support
if(COVERAGE)
    target_compile_options(ufifo_static PRIVATE --coverage -O0)
    target_link_options(ufifo_static PRIVATE --coverage)
    target_compile_options(ufifo_test PRIVATE --coverage -O0)
    target_link_options(ufifo_test PRIVATE --coverage)

    # example targets also link ufifo_static, need --coverage to resolve gcov symbols
    foreach(example ${EXAMPLES})
        target_link_options(${example} PRIVATE --coverage)
    endforeach()

    find_program(LCOV_PATH lcov REQUIRED)
    find_program(GENHTML_PATH genhtml REQUIRED)

    add_custom_target(coverage
        COMMAND ${LCOV_PATH} --zerocounters --directory .
        COMMAND $<TARGET_FILE:ufifo_test>
        COMMAND ${LCOV_PATH} --capture --directory . --output-file coverage_raw.info
            --ignore-errors inconsistent
        COMMAND ${LCOV_PATH} --extract coverage_raw.info
            "*/src/*" "*/inc/*"
            --output-file coverage.info
            --ignore-errors inconsistent
        COMMAND ${GENHTML_PATH} coverage.info --output-directory coverage_report
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS ufifo_test
        COMMENT "Running tests and generating coverage report..."
    )
endif()
