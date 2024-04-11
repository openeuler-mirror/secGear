# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#set auto code prefix
set(PREFIX qingtian_verify_report)

#set sign tool
# set(SIGN_TOOL ${LOCAL_ROOT_PATH}/tools/sign_tool/sign_tool.sh)
set(SIGN_TOOL sign_tool.sh)

#set enclave src code, if any
set(SOURCE_FILES "")

#set log level
set(PRINT_LEVEL 3)
add_definitions(-DPRINT_LEVEL=${PRINT_LEVEL})

if(CC_QT)
    set(OUTPUT att_image.eif) ## Final qingtian enclave image file name, change it to your own.
    set(IMAGE_NAME att_image) ## Docker image name, used to generate qingtian enclave image, change it to your own.
    set(ENCLAVE_ENTRY enclave-main) ## Process running inside qiantian enclave, match with Dockerfile CMD, e.g. CMD ["/home/enclave-main"]

    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.h 
                    ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c 
                    ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)
    
    # tell codegen to yield auto source code
    add_custom_command(OUTPUT ${AUTO_FILES}
                       DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
                       COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE} 
                                          --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/qingtian 
                                          --search-path ${LOCAL_ROOT_PATH}/component/remote_attest/ra_report 
                                          --search-path /usr/include/secGear
    )

    set(COMMON_C_FLAGS "-W -Wall -Werror  -fno-short-enums  -fno-omit-frame-pointer -fstack-protector \
        -Wstack-protector --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra \
        -fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
        -Wno-error=unused-but-set-variable -Wno-error=format-truncation=")

    set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack")

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -s -fPIC")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -ggdb")

    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS}")

    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_BINARY_DIR}/lib/)
    endif()

    # Build enclave source to a library
    add_library(${PREFIX} SHARED ${SOURCE_FILES} ${AUTO_FILES})
    
    target_include_directories( ${PREFIX} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/inc
    ${CMAKE_BINARY_DIR}/inc/secGear
    ${LOCAL_ROOT_PATH}/inc/host_inc/qingtian
    ${LOCAL_ROOT_PATH}/inc/enclave_inc/qingtian
    /usr/include/secGear)

    target_link_libraries(${PREFIX} secgear_tee)
    
    # Build enclave process, linked with the above library
    add_executable(${ENCLAVE_ENTRY} main.c)
    target_link_directories(${ENCLAVE_ENTRY} PRIVATE ${CMAKE_BINARY_DIR}/lib/)
    target_include_directories(${ENCLAVE_ENTRY} PRIVATE /usr/include/secGear)
    target_link_libraries(${ENCLAVE_ENTRY} ${PREFIX} qtsm)
    
    # Build docker image from Docker file, and generate enclave image.
    
endif()

set_target_properties(${PREFIX} PROPERTIES SKIP_BUILD_RPATH TRUE)
