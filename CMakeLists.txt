cmake_minimum_required(VERSION 3.10)
project(ufifo VERSION 1.0.0 LANGUAGES C)

# Options
option(SANITIZER "Enable Address Sanitizer" OFF)

# Compiler settings
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/inc)

# Common compile options
add_compile_options(-g -Os -Wall -Werror)

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
    src/mutex.c
    src/fdlock.c
    src/kfifo.c
    src/ufifo.c
    src/dict.c
)

# Create static library
add_library(ufifo_static STATIC ${LIB_SOURCES})
set_target_properties(ufifo_static PROPERTIES
    OUTPUT_NAME ufifo
    POSITION_INDEPENDENT_CODE ON
)

# Create shared library
add_library(ufifo_shared SHARED ${LIB_SOURCES})
set_target_properties(ufifo_shared PROPERTIES
    OUTPUT_NAME ufifo
    POSITION_INDEPENDENT_CODE ON
)

# Example executables
set(EXAMPLES
    bytestream
    nolock
    record
    record-tag
    record-tag-cb
)

foreach(example ${EXAMPLES})
    add_executable(${example} example/${example}.c)
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
