cmake_minimum_required(VERSION 3.14)
project(ufifo LANGUAGES C CXX)

# Options
set(SANITIZER "" CACHE STRING "Sanitizer to enable: asan, tsan, ubsan (comma-separated, e.g. asan,ubsan)")
option(COVERAGE "Enable code coverage with gcov/lcov" OFF)

# Compiler settings
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_definitions(_GNU_SOURCE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
# (Moved to target_include_directories)

include(GNUInstallDirs)

# Include custom modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(GitVersion)
include(Sanitizers)
include(Coverage)
include(DbgInfo)
include(Doxygen)

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
target_include_directories(ufifo_static PUBLIC inc)
target_compile_options(ufifo_static PRIVATE -g -Os -Wall -Werror)
if(COVERAGE)
    ufifo_enable_coverage(ufifo_static)
endif()

# Create shared library
add_library(ufifo_shared SHARED ${LIB_SOURCES})
set_target_properties(ufifo_shared PROPERTIES
    OUTPUT_NAME ufifo
    VERSION ${UFIFO_VERSION_MAJOR}.${UFIFO_VERSION_MINOR}.${UFIFO_VERSION_PATCH}
    SOVERSION ${UFIFO_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON
)
target_include_directories(ufifo_shared PUBLIC inc)
target_compile_options(ufifo_shared PRIVATE -g -Os -Wall -Werror -fvisibility=hidden)
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

# Generate pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ufifo.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/ufifo.pc
    @ONLY
)

# Install targets
install(FILES inc/ufifo.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ufifo
    COMPONENT release
)

install(TARGETS ufifo_shared ufifo_static
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT release
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT release
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT release
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ufifo.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    COMPONENT release
)

# Use DbgInfo to install targets and separate debug info
ufifo_target_separate_dbginfo(ufifo_shared ${CMAKE_INSTALL_LIBDIR} release dbgsym)
ufifo_target_separate_dbginfo(ufifo_static ${CMAKE_INSTALL_LIBDIR} release dbgsym)

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
