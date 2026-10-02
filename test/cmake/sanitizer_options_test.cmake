cmake_minimum_required(VERSION 3.14)

# Capture directory options without loading a sanitizer runtime in the test process.
function(add_compile_options)
    set(recorded_compile_options "${ARGV}" PARENT_SCOPE)
endfunction()

function(add_link_options)
    set(recorded_link_options "${ARGV}" PARENT_SCOPE)
endfunction()

function(check_sanitizer sanitizer expected_compile_options expected_link_options)
    set(SANITIZER "${sanitizer}")
    set(recorded_compile_options "")
    set(recorded_link_options "")
    include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/Sanitizers.cmake")
    if(NOT "${recorded_compile_options}" STREQUAL "${expected_compile_options}")
        message(FATAL_ERROR "${sanitizer}: unexpected compile options: ${recorded_compile_options}")
    endif()
    if(NOT "${recorded_link_options}" STREQUAL "${expected_link_options}")
        message(FATAL_ERROR "${sanitizer}: unexpected link options: ${recorded_link_options}")
    endif()
endfunction()

set(tsan_compile_options
    "-fsanitize=thread"
    "$<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU>>:-Wno-error=tsan>"
    "$<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wno-error=tsan>"
)
set(asan_compile_options "-fsanitize=address;-fno-omit-frame-pointer;-fno-common")
set(ubsan_compile_options "-fsanitize=undefined;-fno-omit-frame-pointer")

check_sanitizer("" "" "")
check_sanitizer("tsan" "${tsan_compile_options}" "-fsanitize=thread")
check_sanitizer("asan" "${asan_compile_options}" "-fsanitize=address")
check_sanitizer("ubsan" "${ubsan_compile_options}" "-fsanitize=undefined")
check_sanitizer("lsan" "-fsanitize=leak;-fno-omit-frame-pointer" "-fsanitize=leak")
check_sanitizer("asan,ubsan" "${asan_compile_options};${ubsan_compile_options}" "-fsanitize=address;-fsanitize=undefined")
check_sanitizer("tsan,ubsan" "${tsan_compile_options};${ubsan_compile_options}" "-fsanitize=thread;-fsanitize=undefined")
