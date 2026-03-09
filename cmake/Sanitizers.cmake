option(SANITIZER "Sanitizer to enable: asan, tsan, ubsan (comma-separated, e.g. asan,ubsan)" "")

set(SANITIZER_COMPILE_FLAGS "")
set(SANITIZER_LINK_FLAGS "")

if(SANITIZER)
    string(REPLACE "," ";" SANITIZER_LIST "${SANITIZER}")
    list(FIND SANITIZER_LIST "asan" _has_asan)
    list(FIND SANITIZER_LIST "tsan" _has_tsan)
    list(FIND SANITIZER_LIST "ubsan" _has_ubsan)

    # ASan and TSan are mutually exclusive
    if(NOT _has_asan EQUAL -1 AND NOT _has_tsan EQUAL -1)
        message(FATAL_ERROR "ASan and TSan cannot be enabled simultaneously")
    endif()

    if(NOT _has_asan EQUAL -1)
        list(APPEND SANITIZER_COMPILE_FLAGS -fsanitize=address -fno-omit-frame-pointer -fno-common)
        list(APPEND SANITIZER_LINK_FLAGS -fsanitize=address)
    endif()
    if(NOT _has_tsan EQUAL -1)
        list(APPEND SANITIZER_COMPILE_FLAGS -fsanitize=thread)
        list(APPEND SANITIZER_LINK_FLAGS -fsanitize=thread)
    endif()
    if(NOT _has_ubsan EQUAL -1)
        list(APPEND SANITIZER_COMPILE_FLAGS -fsanitize=undefined -fno-omit-frame-pointer)
        list(APPEND SANITIZER_LINK_FLAGS -fsanitize=undefined)
    endif()

    add_compile_options(${SANITIZER_COMPILE_FLAGS})
    add_link_options(${SANITIZER_LINK_FLAGS})
    message(STATUS "Sanitizer enabled: ${SANITIZER}")
endif()
