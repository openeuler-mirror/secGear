# Copyright (c) 2026 secGear contributors.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.16)
project(secgear_starterkit C)

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    message(STATUS "secgear-starterkit SGX example is only enabled on x86_64; skip on ${CMAKE_SYSTEM_PROCESSOR}")
    return()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_SKIP_RPATH TRUE)

set(SECGEAR_INCLUDE_DIR /usr/include/secGear)
set(SECGEAR_LIB /usr/lib64/libsecgear.so)

set(SGX_SDK /opt/intel/sgxsdk)
set(SGX_SDK_INCLUDE_DIR ${SGX_SDK}/include)
set(SGX_SDK_LIB_DIR ${SGX_SDK}/lib64)

include_directories(
    ${SECGEAR_INCLUDE_DIR}
)

add_subdirectory(host)
add_subdirectory(enclave)
