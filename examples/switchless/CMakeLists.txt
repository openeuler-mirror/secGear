# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(Switchless C)

set(CMAKE_C_STANDARD 99)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

#set edl name
set(EDL_FILE switchless.edl)
set(CODEGEN codegen)

if(CC_GP)
    set(CODETYPE trustzone)
    set(UUID f68fd704-6eb1-4d14-b218-722850eb3ef0)
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

