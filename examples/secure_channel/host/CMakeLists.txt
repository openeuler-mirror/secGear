#set host exec name
set(OUTPUT sc_server)
#set host src code
set(SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/server.c)

#set auto code
if(CC_GP)
    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c
                    ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
                        --search-path ${SECGEAR_INSTALL_DIR})
endif()

if(CC_SGX)
    #sgxsdk path
    set(SGX_SDK_PATH ${SDK_PATH})
    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
            --search-path ${SECGEAR_INSTALL_DIR}
            --search-path ${SDK_PATH}/include
            --search-path ${SSL_PATH}/include)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-maybe-uninitialized -fPIE")

if(CC_GP)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/..
            ${CMAKE_CURRENT_BINARY_DIR}
            ${SECGEAR_INSTALL_DIR})
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    target_link_libraries(${OUTPUT} secgear usecure_channel pthread qca)
endif()

if(CC_SGX)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SDK_PATH}/lib64 ${SSL_PATH}/lib64)
    endif()
    set(SGX_MODE HW)
    set(COMMON_CFLAGS "-m64")
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_BINARY_DIR}
        ${SECGEAR_INSTALL_DIR})
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SDK_PATH}/lib64 ${SSL_PATH}/lib64)
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${host_C_Flags}")
    target_link_libraries(${OUTPUT} secgear usecure_channel pthread sgx_usgxssl)
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
