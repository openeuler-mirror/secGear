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

project(switchless C)

set(CMAKE_C_STANDARD 99)

if (NOT DEFINED ENCLAVE)
set(ENCLAVE "SGX")
endif()
set(SGX_SDK_DEFAULT_PATH /opt/intel/sgxsdk)
set(GP_SDK_DEFAULT_PATH /opt/itrustee_sdk)
set(PL_SDK_DEFAULT_PATH /root/dev/sdk)

set(SGX_SSL_DEFAULT_PATH /opt/intel/sgxssl)
set(GP_SSL_DEFAULT_PATH /opt/itrustee_sdk/itrustee_sdk_ssl)

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

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

#set edl name
set(EDL_FILE switchless.edl)
set(CODEGEN codegen)

if(CC_GP)
    set(CODETYPE trustzone)
    set(UUID ebc87fc2-05dc-41b3-85b9-f9f0ef481bad)
    #add_definitions(-DPATH="/data/${UUID}.sec")
    add_definitions(-DPATH="${LOCAL_ROOT_PATH_INSTALL}/data/${UUID}.sec")
endif()

if(CC_SGX)
    set(CODETYPE sgx)
    add_definitions(-DPATH="${CMAKE_CURRENT_BINARY_DIR}/enclave/enclave.signed.so")
endif()


add_subdirectory(${CURRENT_ROOT_PATH}/enclave)
add_subdirectory(${CURRENT_ROOT_PATH}/host)

