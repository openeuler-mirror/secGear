# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#set sign key
set(PEM Enclave_private.pem)
#set sign tool
set(SIGN_TOOL sign_tool.sh)
set(SIGN_CONFIG_PATH ${CMAKE_CURRENT_SOURCE_DIR})
#set enclave src code
set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/enclave.c)

#set log level
set(PRINT_LEVEL 3)
add_definitions(-DPRINT_LEVEL=${PRINT_LEVEL})

#set signed output
set(OUTPUT ${UUID}.sec)

set(WHITE_LIST_0 /vendor/bin/sm_server)
set(WHITE_LIST_OWNER root)
set(WHITELIST WHITE_LIST_0)

set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.h 
    ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c 
    ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)

add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${SECGEAR_INSTALL_DIR})

set(COMMON_C_FLAGS "-W -Wall -Werror  -fno-short-enums  \
    -fno-omit-frame-pointer -fstack-protector \
    -Wstack-protector --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra -nostdinc -nodefaultlibs \
    -fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
    -Wno-error=unused-but-set-variable -Wno-error=format-truncation=")

set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-nostdlib -nodefaultlibs -nostartfiles")

set(CMAKE_C_FLAGS "${COMMON_C_FLAGS}  -march=armv8-a ")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s -fPIC")
set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-s")

set(ITRUSTEE_TEEDIR ${SDK_PATH}/)
set(ITRUSTEE_LIBC ${SDK_PATH}/thirdparty/open_source/musl/libc/)

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${SECGEAR_INSTALL_PATH})
endif()

add_library(${PREFIX} SHARED ${SOURCE_FILES} ${AUTO_FILES})

target_include_directories(${PREFIX} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${SECGEAR_INSTALL_DIR}/
    ${ITRUSTEE_TEEDIR}/include/TA
    ${ITRUSTEE_TEEDIR}/include/TA/huawei_ext
    ${ITRUSTEE_LIBC}/arch/aarch64
    ${ITRUSTEE_LIBC}/
    ${ITRUSTEE_LIBC}/arch/arm/bits
    ${ITRUSTEE_LIBC}/arch/generic
    ${ITRUSTEE_LIBC}/arch/arm)

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(${PREFIX} PRIVATE ${CMAKE_BINARY_DIR}/lib/)
endif()

foreach(WHITE_LIST ${WHITELIST})
    add_definitions(-D${WHITE_LIST}="${${WHITE_LIST}}")
endforeach(WHITE_LIST)
add_definitions(-DWHITE_LIST_OWNER="${WHITE_LIST_OWNER}")

target_link_libraries(${PREFIX} -lsecure_mapping -lsecgear_tee)

message(STATUS "sec image = ${OUTPUT}")
message(STATUS "out path = ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

#for trustzone compiling, you should connact us to get config and private_key.pem for test, so we will not sign and install binary in this example #
add_custom_command(TARGET ${PREFIX}
    POST_BUILD
    COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -c ${SIGN_CONFIG_PATH}/manifest.txt -m ${SIGN_CONFIG_PATH}/config_cloud.ini -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT})

set_target_properties(${PREFIX} PROPERTIES SKIP_BUILD_RPATH TRUE)

install(FILES ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT}
    DESTINATION /data
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE  WORLD_READ  WORLD_EXECUTE)
