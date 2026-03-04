option(COVERAGE "Enable code coverage with gcov/lcov" OFF)

if(COVERAGE)
    # Helper macro to enable coverage for a target
    macro(ufifo_enable_coverage target)
        target_compile_options(${target} PRIVATE --coverage -fprofile-update=atomic -O0)
        target_link_options(${target} PRIVATE --coverage)
    endmacro()

    find_program(LCOV_PATH lcov REQUIRED)
    find_program(GENHTML_PATH genhtml REQUIRED)

    add_custom_target(coverage
        COMMAND ${LCOV_PATH} --zerocounters --directory .
        COMMAND $<TARGET_FILE:ufifo_test>
        COMMAND ${LCOV_PATH} --capture --directory . --output-file coverage_raw.info
            --ignore-errors mismatch,inconsistent,negative,empty
        COMMAND ${LCOV_PATH} --extract coverage_raw.info
            "*/src/*" "*/inc/*"
            --output-file coverage.info
            --ignore-errors mismatch,inconsistent,negative,empty
        COMMAND ${GENHTML_PATH} coverage.info --output-directory coverage_report
            --ignore-errors mismatch,inconsistent,negative,empty
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS ufifo_test
        COMMENT "Running tests and generating coverage report..."
    )
endif()
