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
project(secgear_helloworld VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

#set edl name
set(EDL_FILE helloworld.edl)
set(CODEGEN codegen)

if(CC_QT)
    set(CODETYPE qingtian)
    add_definitions(-DPATH="${CMAKE_BINARY_DIR}/eif/enclave.eif")
    add_definitions(-DQT_ENCLAVE)
endif()

if(CC_GP)
    set(CODETYPE trustzone)
    set(UUID 98937244-1403-4426-ba3c-d75badcdf3ae)
    add_definitions(-DPATH="/data/${UUID}.sec")
endif()

if(CC_SGX)
    set(CODETYPE sgx)
    add_definitions(-DPATH="${CMAKE_CURRENT_BINARY_DIR}/enclave/enclave.signed.so")
endif()

add_subdirectory(${CURRENT_ROOT_PATH}/enclave)
add_subdirectory(${CURRENT_ROOT_PATH}/host)
