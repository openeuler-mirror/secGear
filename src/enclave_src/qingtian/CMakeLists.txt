# Copyright (c) IPADS@SJTU 2021. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TEE_SRC)
set(SOURCE_FILES ${SOURCE_FILES} ${TEE_SRC}
                 ${CMAKE_SOURCE_DIR}/src/common/qingtian/qt_rpc_proxy.c
                 ${CMAKE_SOURCE_DIR}/src/common/qingtian/qt_call.c
                 ${CMAKE_SOURCE_DIR}/component/remote_attest/ra_report/qtsm_attestation_enclave.c)

set(CMAKE_C_FLAGS "${COMMON_C_FLAGS} -fPIC")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")
add_definitions(-DENCLAVE)

add_library(${target_lib} SHARED ${SOURCE_FILES})
target_link_libraries(${target_lib} -lcrypto)

target_include_directories(${target_lib} PRIVATE
    ${LOCAL_ROOT_PATH}/inc/enclave_inc/qingtian
    ${LOCAL_ROOT_PATH}/inc/host_inc/qingtian
    ${LOCAL_ROOT_PATH}/inc/common/qingtian
    ${LOCAL_ROOT_PATH}/inc/thirdparty/qtsm)

install(TARGETS  ${target_lib}
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)