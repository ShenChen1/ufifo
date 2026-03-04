option(UFIFO_SEPARATE_DBGINFO "Separate debug symbols for Release builds" OFF)

function(ufifo_target_separate_dbginfo TARGET DESTINATION_DIR MAIN_COMPONENT DBG_COMPONENT)
    install(TARGETS ${TARGET}
        LIBRARY DESTINATION ${DESTINATION_DIR} COMPONENT ${MAIN_COMPONENT}
        ARCHIVE DESTINATION ${DESTINATION_DIR} COMPONENT ${MAIN_COMPONENT}
        RUNTIME DESTINATION ${DESTINATION_DIR} COMPONENT ${MAIN_COMPONENT}
    )

    if(UFIFO_SEPARATE_DBGINFO)
        get_target_property(target_type ${TARGET} TYPE)
        if(target_type STREQUAL "SHARED_LIBRARY" OR target_type STREQUAL "EXECUTABLE")
            # Generate the .debug file after build
            add_custom_command(TARGET ${TARGET} POST_BUILD
                COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE_NAME:${TARGET}> $<TARGET_FILE_NAME:${TARGET}>.debug
                COMMAND ${CMAKE_STRIP} --strip-debug --strip-unneeded $<TARGET_FILE_NAME:${TARGET}>
                COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=$<TARGET_FILE_NAME:${TARGET}>.debug $<TARGET_FILE_NAME:${TARGET}>
                WORKING_DIRECTORY $<TARGET_FILE_DIR:${TARGET}>
                COMMENT "Separating debug info for ${TARGET}"
            )
            # Install the generated .debug file into the debug component
            install(FILES $<TARGET_FILE:${TARGET}>.debug
                DESTINATION ${DESTINATION_DIR}
                COMPONENT ${DBG_COMPONENT}
                OPTIONAL
            )
        elseif(target_type STREQUAL "STATIC_LIBRARY")
            add_custom_command(TARGET ${TARGET} POST_BUILD
                COMMAND ${CMAKE_STRIP} -g $<TARGET_FILE:${TARGET}>
                COMMENT "Stripping static library ${TARGET}"
            )
        endif()
    endif()
endfunction()
