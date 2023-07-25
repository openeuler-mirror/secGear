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
project(secGear C)
 
set(CMAKE_C_STANDARD 99)
 
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
 
set(LOCAL_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

 
set(SECGEAR_DEBUG_LEVEL SECGEAR_LOG_LEVEL_DEBUG)
add_definitions(-DSECGEAR_DEBUG_LEVEL=${SECGEAR_DEBUG_LEVEL})
 
option(CC_GP  "default off" OFF)
option(CC_SGX "default off" OFF)
if(CMAKE_BUILD_TYPE MATCHES "Debug")
	add_definitions(-DDEBUG_FILE_LINE)
endif()
set(CMAKE_C_FLAGS "-fstack-protector-all -W -Wall -Werror -Wextra -Werror=array-bounds -D_FORTIFY_SOURCE=2 -O2 -ftrapv")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -s")

set(CMAKE_EXE_LINKER_FLAGS    "-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack")

if(CC_GP)
	if(NOT IS_DIRECTORY ${iTrusteeSDK})
		message(FATAL_ERROR "Please provide the correct iTrusteeSDK path")
	endif()
endif()

if(CC_SGX)
	if(NOT IS_DIRECTORY ${SGXSDK})
		message(FATAL_ERROR "Please provide the correct SGXSDK path")
	endif()
endif()

add_subdirectory(tools/codegener)

add_subdirectory(src)

execute_process(COMMAND mkdir ${LOCAL_ROOT_PATH}/bin)

add_subdirectory(examples)


install(FILES ${LOCAL_ROOT_PATH}/conf/logrotate.d/secgear
        DESTINATION /etc/logrotate.d/)

install(FILES ${LOCAL_ROOT_PATH}/conf/rsyslog.d/secgear.conf
        DESTINATION /etc/rsyslog.d/)

