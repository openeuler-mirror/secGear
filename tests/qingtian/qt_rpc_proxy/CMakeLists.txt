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
project(qt_rpc_proxy_test C)

set(CMAKE_C_STANDARD 99)


set(CMAKE_C_FLAGS "-g -fstack-protector-all -W -Wall -Werror -Wextra -Werror=array-bounds -ftrapv")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -s")

set(CMAKE_EXE_LINKER_FLAGS    "-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack")
add_definitions(-DQT_ENCLAVE)
add_definitions(-DSIM)


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../inc/common/qingtian/
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../inc/host_inc/
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../inc/enclave_inc/qingtian/
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../inc/thirdparty/qtsm/)

set(SOURCE_FILES qt_rpc_proxy_test.c ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/common/qingtian/qt_rpc_proxy.c)

set(HOST_TARGET proxy_host)
add_executable(${HOST_TARGET} ${SOURCE_FILES})
target_link_libraries(${HOST_TARGET} pthread -lcrypto)


set(ENCLAVE_TARGET proxy_enclave)
set(ENCLAVE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../../../src/enclave_src/qingtian/qingtian_enclave_init.c)
add_executable(${ENCLAVE_TARGET} ${SOURCE_FILES} ${ENCLAVE_FILES})
target_link_libraries(${ENCLAVE_TARGET} pthread -lcrypto)
set_target_properties(${ENCLAVE_TARGET} PROPERTIES COMPILE_FLAGS "-DQT_SERVER")
