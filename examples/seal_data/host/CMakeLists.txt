# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#set auto code prefix
set(PREFIX seal_data)
#set host exec name
set(OUTPUT secgear_seal_data)
#set host src code
set(SOURCE_FILE main.c)
#set auto code
if(CC_GP)
    set(AUTO_FILES  ${PREFIX}_u.h ${PREFIX}_u.c ${PREFIX}_args.h)
    set(SEARCH_PATH ${LOCAL_ROOT_PATH}/inc/host_inc/gp)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${SEARCH_PATH})
endif()

if(CC_SGX)
    set(AUTO_FILES  ${PREFIX}_u.h ${PREFIX}_u.c)
    set(SEARCH_PATH ${LOCAL_ROOT_PATH}/inc/host_inc/sgx)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${SEARCH_PATH} --search-path ${SGXSDK}/include)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s")

if(CC_GP)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE
            ${CMAKE_BINARY_DIR}/inc
            ${LOCAL_ROOT_PATH}/inc/host_inc
            ${LOCAL_ROOT_PATH}/inc/host_inc/gp
            ${CMAKE_CURRENT_BINARY_DIR})
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
endif()

if(CC_SGX)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE
                    ${LOCAL_ROOT_PATH}/inc/host_inc
                    ${LOCAL_ROOT_PATH}/inc/host_inc/sgx
                    ${CMAKE_CURRENT_BINARY_DIR})
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
endif()

if(CC_SIM)
    target_link_libraries(${OUTPUT} secgearsim pthread)
else()
    target_link_libraries(${OUTPUT} secgear pthread)
endif()
set_target_properties(${OUTPUT} PROPERTIES SKIP_BUILD_RPATH TRUE)

if(CC_GP)
        #itrustee install whitelist /vender/bin/teec_hello
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

