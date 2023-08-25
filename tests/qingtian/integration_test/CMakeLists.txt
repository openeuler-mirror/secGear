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
project(secgear_test VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)
set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_FLAGS "-Wno-deprecated-declarations")

#set edl name
set(EDL_FILE test_ta.edl)
set(CODEGEN codegen)

if(CC_QT)
    set(CODETYPE qingtian)
    add_definitions(-DPATH="${CMAKE_BINARY_DIR}/eif/test_ta.eif")
    add_definitions(-DQT_ENCLAVE)
endif()

set(PREFIX test_ta)
set(CA_FILES test_ca.cc)

#set auto code
set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c)
add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/${EDL_FILE} --search-path /usr/include/secGear)

add_subdirectory(test_ta)

set(SOURCE_FILES test_main.cc ${CA_FILES} ${AUTO_FILES})

add_executable(secgear_test ${SOURCE_FILES})
target_include_directories(secgear_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR} /usr/include/secGear)
target_link_libraries(secgear_test gtest secgear)

add_test(NAME secgear_test COMMAND secgear_test)
