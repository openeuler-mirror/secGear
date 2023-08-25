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

#set sign tool
set(SIGN_TOOL sign_tool.sh)

#set enclave src code
set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/test_ta.c)

if(CC_QT)
    #set signed output
    set(OUTPUT test_ta.eif)
    set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c)
    add_custom_command(OUTPUT ${AUTO_FILES}
        DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
        COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
        --search-path /usr/include/secGear)

endif()

if (CC_QT)
    set(COMMON_C_FLAGS "-W -Wall -Werror -g -fno-short-enums  -fno-omit-frame-pointer -fstack-protector \
        -Wstack-protector --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra \
        -fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
        -Wno-error=unused-but-set-variable -Wno-error=format-truncation=")

    set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack")
endif()

if(CC_QT)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -s -fPIC")
    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS}")

    add_library(${PREFIX} SHARED ${SOURCE_FILES} ${AUTO_FILES})
    target_include_directories(${PREFIX} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} /usr/include/secGear)
    target_link_libraries(${PREFIX} -lsecgear_tee)

    set(ENCLAVE_ENTRY enclave)
    add_executable(${ENCLAVE_ENTRY} docker_main.c)
    target_link_directories(${ENCLAVE_ENTRY} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${ENCLAVE_ENTRY} -ltest_ta -lqtsm)
    target_include_directories(${ENCLAVE_ENTRY} PRIVATE /usr/include/secGear)
    
    set(IMAGE_NAME enclave_image)
    add_custom_command(TARGET ${ENCLAVE_ENTRY}
        POST_BUILD
        COMMAND mkdir -p  ${CMAKE_BINARY_DIR}/eif
        COMMAND cp /usr/lib64/libqtsm.so ${CMAKE_BINARY_DIR}/eif
        COMMAND cp /usr/lib64/libsecgear_tee.a ${CMAKE_BINARY_DIR}/eif
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/libtest_ta.so ${CMAKE_BINARY_DIR}/eif
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/enclave ${CMAKE_BINARY_DIR}/eif
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile ${CMAKE_BINARY_DIR}/eif
        COMMAND docker build -t ${IMAGE_NAME} ${CMAKE_BINARY_DIR}/eif
        COMMAND bash ${SIGN_TOOL} -d sign -x qingtian -i ${IMAGE_NAME} -o ${CMAKE_BINARY_DIR}/eif/${OUTPUT}
        )

endif()

#set_target_properties(${PREFIX} PROPERTIES SKIP_BUILD_RPATH TRUE)
