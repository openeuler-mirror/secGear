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
project(secure_mapping C)

set(CMAKE_C_STANDARD 99)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(PREFIX sm_demo)
set(ENCLAVE "GP")
set(CC_GP ON)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(EDL_FILE sm_demo.edl)
set(CODEGEN codegen)

set(SECGEAR_INSTALL_DIR /usr/include/secGear)

set(CODETYPE trustzone)
set(UUID c1edecce-fef4-11ef-9821-c8a776e83705)
add_definitions(-DPATH="${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${UUID}.sec")

add_subdirectory(${CURRENT_ROOT_PATH}/enclave)
add_subdirectory(${CURRENT_ROOT_PATH}/host)
