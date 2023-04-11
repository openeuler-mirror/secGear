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
message("=============cmake help info=======================") 
message("Example default cmd: cmake ..")
message("same with default: cmake -DENCLAVE=SGX -DSDK_PATH=/opt/intel/sgxsdk -DSSL_PATH=/opt/intel/sgxssl ..")
message("cmake [-DCMAKE_BUILD_TYPE=val] [-DENCLAVE=val] [-DCC_SIM=ON] [-DSDK_PATH=path] [-DSSL_PATH=path] ..")
message("CMAKE_BUILD_TYPE:[optional] pass Debug if you need file line info in log, default log without file line")
message("ENCLAVE:[optional] valid val: SGX --default, GP --trustzone, PL --Penglai")
message("CC_SIM:[optional] only support by SGX")
message("SDK_PATH:[optional] default SGX:/opt/intel/sgxsdk, GP:/opt/itrustee_sdk, PL:/root/dev/sdk;
	 pass SDK_PATH if you installed sdk in custom path")
message("SSL_PATH:[optional] pass security ssl installed path when your application use ssl")
message("=============cmake help info=======================") 
if (NOT DEFINED ENCLAVE)
	set(ENCLAVE "SGX")
endif()
set(SGX_SDK_DEFAULT_PATH /opt/intel/sgxsdk)
set(GP_SDK_DEFAULT_PATH /opt/itrustee_sdk)
set(PL_SDK_DEFAULT_PATH /root/dev/sdk)

if (NOT DEFINED SSL_PATH)
set(SSL_PATH /opt/intel/sgxssl)
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug")
	add_definitions(-DDEBUG_FILE_LINE)
endif()

if(COVERAGE_ENABLE)
	message(STATUS "Enable coverage compile option")
	set(COVERAGE_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage")
endif(COVERAGE_ENABLE)

if(ASAN_ENABLE)
	message(STATUS "Enable asan compile option")
	set(ASAN_OPTIONS "${ASAN_OPTION} -fsanitize=address -fsanitize-recover=address")
endif(ASAN_ENABLE)

set(CMAKE_C_FLAGS "-fstack-protector-all -W -Wall -Werror -Wextra -Werror=array-bounds -D_FORTIFY_SOURCE=2 -O2 -ftrapv")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COVERAGE_OPTION} ${ASAN_OPTIONS}")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -s")

set(CMAKE_EXE_LINKER_FLAGS    "-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack")

if(${ENCLAVE} STREQUAL "GP")
	if (NOT DEFINED SDK_PATH)
		set(iTrusteeSDK ${GP_SDK_DEFAULT_PATH})
	else()
		set(iTrusteeSDK ${SDK_PATH})
	endif()
	message("Current Platform: ARM Trustzone, iTrustee SDK PATH:${iTrusteeSDK}")
	if(NOT IS_DIRECTORY ${iTrusteeSDK})
		message(FATAL_ERROR "Please provide the correct iTrusteeSDK path")
	endif()
	set(CC_GP ON)
endif()

if(${ENCLAVE} STREQUAL "SGX")
	if (NOT DEFINED SDK_PATH)
		set(SGXSDK ${SGX_SDK_DEFAULT_PATH})
	else()
		set(SGXSDK ${SDK_PATH})
	endif()
	message("Current Platform: Intel SGX, SGX SDK PATH:${SGXSDK}")
	if(NOT IS_DIRECTORY ${SGXSDK})
		message(FATAL_ERROR "Please provide the correct SGXSDK path")
	endif()
	set(CC_SGX ON)
endif()

if(${ENCLAVE} STREQUAL "PL")
	if (NOT DEFINED SDK_PATH)
		set(PLSDK ${PL_SDK_DEFAULT_PATH})
        else()
		set(PLSDK ${SDK_PATH})
	endif()
	message("Current Platform: RISC-V, Penglai SDK PATH:${PLSDK}")
	if(NOT IS_DIRECTORY ${PLSDK})
		message(FATAL_ERROR "Please provide the correct Penglai SDK path")
	endif()
	set(CC_PL ON)
endif()

add_subdirectory(tools/codegener)

add_subdirectory(src)
add_subdirectory(component)

if(NOT IS_DIRECTORY ${LOCAL_ROOT_PATH}/bin)
	execute_process(COMMAND mkdir ${LOCAL_ROOT_PATH}/bin)
endif()

add_subdirectory(examples)
add_subdirectory(test)

install(FILES ${LOCAL_ROOT_PATH}/conf/logrotate.d/secgear
        DESTINATION ${LOCAL_ROOT_PATH_INSTALL}/etc/logrotate.d/)

install(FILES ${LOCAL_ROOT_PATH}/conf/rsyslog.d/secgear.conf
        DESTINATION ${LOCAL_ROOT_PATH_INSTALL}/etc/rsyslog.d/)

install(FILES ${LOCAL_ROOT_PATH}/tools/sign_tool/sign_tool.sh
        DESTINATION ${LOCAL_ROOT_PATH_INSTALL}/usr/bin/
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
set(SIGN_FILE 
    ${LOCAL_ROOT_PATH}/tools/sign_tool/generate_signature.py
    ${LOCAL_ROOT_PATH}/tools/sign_tool/manifest.py
    ${LOCAL_ROOT_PATH}/tools/sign_tool/signtool_v3.py
)
install(FILES ${SIGN_FILE}
        DESTINATION ${LOCAL_ROOT_PATH_INSTALL}/lib/secGear/)
