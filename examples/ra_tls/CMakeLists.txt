# Copyright 2024 Huawei Technologies Co., Ltd. 2024. All rights reserved.
# ra_tls is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(ra_tls_ex VERSION 0.1)

set(SERVER_NAME server)
set(SERVER_SRC ${CMAKE_CURRENT_SOURCE_DIR}/server.c)
set(CLIENT_NAME client)
set(CLIENT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/client.c)

set(LD_SO crypto ssl ra_tls)
add_definitions(-DUSE_OPENSSL)
#uncomment below when client use certificate
add_definitions(-DCLIENT_WITH_CERT)
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "${CMAKE_INSTALL_PREFIX}/lib64")
find_library(DEP_LIBS_PATH NAMES ${LD_SO} PATH ${CMAKE_LIBRARY_PATH})

add_executable(${SERVER_NAME} ${SERVER_SRC})
add_executable(${CLIENT_NAME} ${CLIENT_SRC})

include_directories(${SERVER_NAME} /usr/include/secGear)
include_directories(${CLIENT_NAME} /usr/include/secGear)

target_link_libraries(${SERVER_NAME} ${LD_SO})
target_link_libraries(${CLIENT_NAME} ${LD_SO})