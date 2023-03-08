#set host exec name
set(OUTPUT sc_client_with_recv_thread)
#set host src code
set(SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/client.c)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-maybe-uninitialized -fPIE")

if(CC_GP)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_BINARY_DIR}/inc
            ${CMAKE_CURRENT_SOURCE_DIR}/..
            /usr/include/secGear)
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    target_link_libraries(${OUTPUT} secgear pthread csecure_channel)
endif()

if(CC_SGX)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SGX_SDK_PATH}/lib64)
    endif()
    set(SGX_MODE HW)
    set(COMMON_CFLAGS "-m64")
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${LOCAL_ROOT_PATH}/inc/host_inc
        ${LOCAL_ROOT_PATH}/inc/host_inc/sgx
        ${LOCAL_ROOT_PATH}/component/secure_channel
        ${LOCAL_ROOT_PATH}/component/secure_channel/client)
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SGX_SDK_PATH}/lib64)
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${host_C_Flags}")
    target_link_libraries(${OUTPUT} secgear csecure_channel pthread ssl crypto)
endif()

set_target_properties(${OUTPUT} PROPERTIES SKIP_BUILD_RPATH TRUE)

if(CC_GP)
    install(TARGETS  ${OUTPUT}
            RUNTIME
            DESTINATION /vendor/bin/
            PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
endif()

if(CC_SGX)
    install(TARGETS  ${OUTPUT}
            RUNTIME
            DESTINATION ${CMAKE_BINARY_DIR}/bin/
            PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
endif()
