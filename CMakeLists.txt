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
    src/ufifo_opts.c
    src/ufifo_sync.c
    src/ufifo_epoll.c
    src/ufifo_init.c
    src/ufifo_info.c
)

# liburing library (built from third_party/liburing submodule)
include(ExternalProject)

set(LIBURING_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/liburing")
set(LIBURING_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/liburing_install")
set(LIBURING_INCLUDE_DIR "${LIBURING_INSTALL_DIR}/include")
set(LIBURING_LIB "${LIBURING_INSTALL_DIR}/lib/liburing.a")

if(NOT EXISTS "${LIBURING_SOURCE_DIR}/configure")
    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
        message(STATUS "Submodule third_party/liburing not initialized, updating...")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive third_party/liburing
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            RESULT_VARIABLE GIT_SUBMOD_RESULT
        )
        if(NOT GIT_SUBMOD_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to initialize submodule third_party/liburing")
        endif()
    else()
        message(FATAL_ERROR "third_party/liburing is missing and git is not available.")
    endif()
endif()

file(MAKE_DIRECTORY "${LIBURING_INCLUDE_DIR}")

ExternalProject_Add(liburing_ep
    SOURCE_DIR "${LIBURING_SOURCE_DIR}"
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=${LIBURING_INSTALL_DIR} --libdir=${LIBURING_INSTALL_DIR}/lib --includedir=${LIBURING_INCLUDE_DIR}
    BUILD_COMMAND make "CFLAGS=-fPIC -O3" -C src liburing.a
    INSTALL_COMMAND make -C src install prefix=${LIBURING_INSTALL_DIR} includedir=${LIBURING_INCLUDE_DIR} libdevdir=${LIBURING_INSTALL_DIR}/lib libdir=${LIBURING_INSTALL_DIR}/lib
    BUILD_BYPRODUCTS "${LIBURING_LIB}"
)

add_library(liburing STATIC IMPORTED GLOBAL)
set_target_properties(liburing PROPERTIES
    IMPORTED_LOCATION "${LIBURING_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBURING_INCLUDE_DIR}"
)

# Create static library
add_library(ufifo_static STATIC ${LIB_SOURCES})
add_dependencies(ufifo_static liburing_ep)
set_target_properties(ufifo_static PROPERTIES
    OUTPUT_NAME ufifo
    POSITION_INDEPENDENT_CODE ON
)
target_include_directories(ufifo_static PUBLIC inc)
target_link_libraries(ufifo_static PUBLIC liburing)
target_compile_options(ufifo_static PRIVATE -g -O3 -Wall -Werror)
if(COVERAGE)
    ufifo_enable_coverage(ufifo_static)
endif()

# Create shared library
add_library(ufifo_shared SHARED ${LIB_SOURCES})
add_dependencies(ufifo_shared liburing_ep)
set_target_properties(ufifo_shared PROPERTIES
    OUTPUT_NAME ufifo
    VERSION ${UFIFO_VERSION_MAJOR}.${UFIFO_VERSION_MINOR}.${UFIFO_VERSION_PATCH}
    SOVERSION ${UFIFO_VERSION_MAJOR}
    POSITION_INDEPENDENT_CODE ON
)
target_include_directories(ufifo_shared PUBLIC inc)
target_link_libraries(ufifo_shared PRIVATE liburing)
target_compile_options(ufifo_shared PRIVATE -g -O3 -flto -Wall -Werror -fvisibility=hidden)
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
    target_compile_options(${example} PRIVATE -g -O3 -Wall -Werror)
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
