cmake_minimum_required(VERSION 3.14)
project(ufifo LANGUAGES C CXX)

# Options
set(SANITIZER "" CACHE STRING "Sanitizer to enable: asan, tsan, ubsan (comma-separated, e.g. asan,ubsan)")
option(COVERAGE "Enable code coverage with gcov/lcov" OFF)

# Compiler settings
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_definitions(_GNU_SOURCE)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/inc)

# Include custom modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(GitVersion)
include(Sanitizers)
include(Coverage)
include(DbgInfo)

# Find required libraries
find_library(RT_LIBRARY rt)
find_library(PTHREAD_LIBRARY pthread)

# Library source files
set(LIB_SOURCES
    src/kfifo.c
    src/ufifo_opts.c
    src/ufifo_sync.c
    src/ufifo_epoll.c
    src/ufifo_init.c
    src/ufifo_info.c
)

# Create static library
add_library(ufifo_static STATIC ${LIB_SOURCES})
set_target_properties(ufifo_static PROPERTIES
    OUTPUT_NAME ufifo
    POSITION_INDEPENDENT_CODE ON
)
target_compile_options(ufifo_static PRIVATE -g -Os -Wall -Werror)
if(COVERAGE)
    ufifo_enable_coverage(ufifo_static)
endif()

# Create shared library
add_library(ufifo_shared SHARED ${LIB_SOURCES})
set_target_properties(ufifo_shared PROPERTIES
    OUTPUT_NAME ufifo
    POSITION_INDEPENDENT_CODE ON
)
target_compile_options(ufifo_shared PRIVATE -g -Os -Wall -Werror)
if(COVERAGE)
    ufifo_enable_coverage(ufifo_shared)
endif()

# Example executables
set(EXAMPLES
    bytestream
    nolock
    pressure
    record
    record-tag
    record-tag-cb
    epoll
)

foreach(example ${EXAMPLES})
    add_executable(${example} example/${example}.c)
    target_compile_options(${example} PRIVATE -g -Os -Wall -Werror)
    target_link_libraries(${example} PRIVATE ufifo_static ${RT_LIBRARY} ${PTHREAD_LIBRARY})
endforeach()

# Install targets
install(FILES inc/ufifo.h
    DESTINATION include/ufifo
    COMPONENT release
)

# Use DbgInfo to install targets and separate debug info
ufifo_target_separate_dbginfo(ufifo_shared lib release dbgsym)
ufifo_target_separate_dbginfo(ufifo_static lib release dbgsym)

# Test target
enable_testing()
foreach(example ${EXAMPLES})
    add_test(NAME ${example} COMMAND ${example})
endforeach()

include(GTest)

# Setup CPack for generating deb, rpm, tar files
set(CPACK_PACKAGE_NAME "ufifo")
set(CPACK_PACKAGE_VENDOR "Peter Shen")
set(CPACK_PACKAGE_VERSION_MAJOR ${UFIFO_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${UFIFO_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${UFIFO_VERSION_PATCH})

# CPack generator settings
set(CPACK_GENERATOR "TGZ")
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON) # Install each component as separate archive
set(CPACK_COMPONENTS_ALL release dbgsym)

include(CPack)
