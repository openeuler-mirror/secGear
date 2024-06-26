# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(Switchless C)

set(CMAKE_C_STANDARD 99)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

if (NOT DEFINED ENCLAVE)
    set(ENCLAVE "SGX")
endif()
set(SGX_SDK_DEFAULT_PATH /opt/intel/sgxsdk)
set(GP_SDK_DEFAULT_PATH /opt/itrustee_sdk)
set(PL_SDK_DEFAULT_PATH /root/dev/sdk)

if (NOT DEFINED SSL_PATH)
    set(SSL_PATH /opt/intel/sgxssl)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(${ENCLAVE} STREQUAL "GP")
    if (NOT DEFINED SDK_PATH)
        set(SDK_PATH ${GP_SDK_DEFAULT_PATH})
    else()
        set(SDK_PATH ${SDK_PATH})
    endif()
    message("Current Platform: ARM Trustzone, iTrustee SDK PATH:${SDK_PATH}")
    if(NOT IS_DIRECTORY ${SDK_PATH})
        message(FATAL_ERROR "Please provide the correct SDK_PATH path")
    endif()
    set(CC_GP ON)
endif()

if(${ENCLAVE} STREQUAL "SGX")
    if (NOT DEFINED SDK_PATH)
        set(SDK_PATH ${SGX_SDK_DEFAULT_PATH})
    else()
        set(SDK_PATH ${SDK_PATH})
    endif()
    message("Current Platform: Intel SGX, SGX SDK PATH:${SDK_PATH}")
    if(NOT IS_DIRECTORY ${SDK_PATH})
        message(FATAL_ERROR "Please provide the correct SDK_PATH path")
    endif()
    set(CC_SGX ON)
endif()

if(${ENCLAVE} STREQUAL "PL")
    if (NOT DEFINED SDK_PATH)
        set(SDK_PATH ${PL_SDK_DEFAULT_PATH})
    else()
        set(SDK_PATH ${SDK_PATH})
    endif()
    message("Current Platform: Penglai, PL SDK PATH:${SDK_PATH}")
    if(NOT IS_DIRECTORY ${SDK_PATH})
        message(FATAL_ERROR "Please provide the correct SDK_PATH path")
    endif()
    set(CC_PL ON)
endif()

#set edl name
set(EDL_FILE switchless.edl)
set(CODEGEN codegen)

set(SECGEAR_INSTALL_DIR /usr/include/secGear)

if(CC_GP)
    set(CODETYPE trustzone)
    set(UUID 92b56ae2-d3e2-4322-87ac-6a51f1824347)
    add_definitions(-DPATH="/data/${UUID}.sec")
endif()

if(CC_SGX)
    set(CODETYPE sgx)
    add_definitions(-DPATH="${CMAKE_CURRENT_BINARY_DIR}/enclave/enclave.signed.so")
endif()

if(CC_PL)
    message(FATAL_ERROR "The PL platform does not support switchless.")
endif()

add_subdirectory(${CURRENT_ROOT_PATH}/enclave)
add_subdirectory(${CURRENT_ROOT_PATH}/host)

