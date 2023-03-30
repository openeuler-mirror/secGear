# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(secure_channel_host C)

#set host src code
set(SOURCE_FILE secure_channel_host.c)

#set auto code
if(CC_GP)
    set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --header-only --untrusted ${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/gp)
endif()
    
if(CC_SGX)
    #sgxsdk path
    set(SGX_SDK_PATH ${SGXSDK})
    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --header-only --untrusted ${EDL_FILE} 
                    --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/sgx
                    --search-path ${SSL_PATH}/include 
                    --search-path ${SGX_SDK_PATH}/include)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-maybe-uninitialized -fPIC")
 
if(CC_GP)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        ${CMAKE_BINARY_DIR}/lib/)
    endif()

    include_directories(
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}/inc
        ${LOCAL_ROOT_PATH}/component/secure_channel
        ${iTrusteeSDK}/include/CA
        ${LOCAL_ROOT_PATH}/inc/host_inc
        ${LOCAL_ROOT_PATH}/inc/host_inc/gp)
    add_library(u${PREFIX} SHARED ${SOURCE_FILE} ${AUTO_FILES})

    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(u${PREFIX} PRIVATE 
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
endif()
 
if(CC_SGX)
    set(SGX_MODE HW)
    set(COMMON_CFLAGS "-m64")
    if(${SGX_MODE} STREQUAL HW)
        set(Urts_Library_Name sgx_urts)
    else()
        set(Urts_Library_Name sgx_urts_sim)
    endif()
    set(host_C_Flags "${COMMON_CFLAGS} -fPIC -Wno-attributes -lz -pthread")

    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        ${CMAKE_BINARY_DIR}/lib/)
    endif()

    include_directories(
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LOCAL_ROOT_PATH}/component/secure_channel
        ${LOCAL_ROOT_PATH}/inc/host_inc
        ${LOCAL_ROOT_PATH}/inc/host_inc/sgx
        ${OPENSSL_PATH}/include
        ${SGX_SDK_PATH}/include)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${host_C_Flags}")
    add_library(u${PREFIX} SHARED ${SOURCE_FILE} ${AUTO_FILES})

    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
	    target_link_directories(u${PREFIX} PRIVATE 
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
            ${CMAKE_BINARY_DIR}/lib/)
    endif()
endif()

set(LIBRARY_INSTALL ${LOCAL_ROOT_PATH_INSTALL}/usr/lib64)

install(TARGETS u${PREFIX} 
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)


