# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(secure_channel_enclave C)
set(PREFIX secure_channel)

set(SOURCE_FILES secure_channel_enclave.c ${CMAKE_CURRENT_SOURCE_DIR}/../secure_channel_common.c)

set(PRINT_LEVEL 3)
add_definitions(-DPRINT_LEVEL=${PRINT_LEVEL})

if(CC_GP)
    add_definitions(-DGP_ENCLAVE)
    set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --header-only --trusted ${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/gp)
endif()

if(CC_SGX)
    add_definitions(-DSGX_ENCLAVE)
    #sgxsdk path
    set(SGX_SDK_PATH ${SGXSDK})
    set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.h)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --header-only --trusted ${EDL_FILE}
                    --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/sgx
                    --search-path ${SSL_PATH}/include
                    --search-path ${SGX_SDK_PATH}/include)
endif()

set(CMAKE_C_FLAGS "-W -Wall -fno-short-enums -fno-omit-frame-pointer -fstack-protector \
    -Wstack-protector --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra -nostdinc -nodefaultlibs\
    -fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
    -Wno-error=unused-but-set-variable -Wno-error=format-truncation= ")

set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-nostdlib -nodefaultlibs -nostartfiles")

if(CC_GP)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a -fPIC")
    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-s")

    set(ITRUSTEE_TEEDIR ${iTrusteeSDK}/)
    # set(ITRUSTEE_LIBC ${iTrusteeSDK}/thirdparty/musl/musl-1.2.0/)
    set(ITRUSTEE_LIBC ${iTrusteeSDK}/thirdparty/open_source/musl/libc)

    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${CMAKE_BINARY_DIR}/lib/)
    endif()

    include_directories(
            ${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${LOCAL_ROOT_PATH}/component/secure_channel
            ${LOCAL_ROOT_PATH}/inc/host_inc
            ${LOCAL_ROOT_PATH}/inc/host_inc/gp
            ${LOCAL_ROOT_PATH}/inc/enclave_inc
            ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp
            ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee
            ${ITRUSTEE_TEEDIR}/include/TA
            ${ITRUSTEE_TEEDIR}/include/TA/huawei_ext
            ${ITRUSTEE_TEEDIR}/include/TA/openssl
            ${ITRUSTEE_LIBC}/arch/aarch64
            ${ITRUSTEE_LIBC}/
            ${ITRUSTEE_LIBC}/arch/arm/bits
            ${ITRUSTEE_LIBC}/arch/generic
            ${ITRUSTEE_LIBC}/arch/arm
            ${SSL_PATH}/include)
    add_library(t${PREFIX} ${SOURCE_FILES} ${AUTO_FILES} ${LOCAL_ROOT_PATH}/src/enclave_src/gp/gp.c)

    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(t${PREFIX} PRIVATE
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
            ${CMAKE_BINARY_DIR}/lib/)
    endif()
else()
    set(SGX_MODE HW)
    set(CMAKE_C_FLAGS "${COMMON_C_FLAGS} -m64 -pthread -fPIC")

    set(OPENSSL_LIBRARY_PATH ${SSL_PATH}/lib64)
    set(SGX_LIBRARY_PATH ${SGX_SDK_PATH}/lib64)

    if(${SGX_MODE} STREQUAL HW)
        set(Trts_Library_Name sgx_trts)
        set(Service_Library_Name sgx_tservice)
    else()
        set(Trts_Library_Name sgx_trts_sim)
        set(Service_Library_Name sgx_tservice_sim)
    endif()

    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-z,defs -Wl,-pie -Bstatic -Bsymbolic -eenclave_entry \
    -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/Enclave.lds")

    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SGX_LIBRARY_PATH})
    endif()

    include_directories(
        ${CMAKE_CURRENT_BINARY_DIR}
        ${LOCAL_ROOT_PATH}/component/secure_channel
        ${LOCAL_ROOT_PATH}/inc/host_inc
        ${LOCAL_ROOT_PATH}/inc/host_inc/sgx
        ${LOCAL_ROOT_PATH}/inc/enclave_inc
        ${LOCAL_ROOT_PATH}/inc/enclave_inc/sgx
        ${SSL_PATH}/include
        ${SGX_SDK_PATH}/include/tlibc
        ${SGX_SDK_PATH}/include/libcxx
        ${SGX_SDK_PATH}/include)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${Enclave_C_Flags}")
    add_library(t${PREFIX} ${SOURCE_FILES} ${AUTO_FILES}) 

    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(t${PREFIX} PRIVATE
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SGX_LIBRARY_PATH} ${OPENSSL_LIBRARY_PATH})
    endif()
endif()

set(LIBRARY_INSTALL ${LOCAL_ROOT_PATH_INSTALL}/usr/lib64)

install(TARGETS t${PREFIX} 
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
