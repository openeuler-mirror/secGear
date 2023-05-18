# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(sg_ra_report C)

set(TARGET secgear_ra)
aux_source_directory(. SRC_FILES)
aux_source_directory(${LOCAL_ROOT_PATH}/thirdparty/cjson/ CJSON_SRC)
FILE (GLOB_RECURSE BASE64_SRC "${LOCAL_ROOT_PATH}/thirdparty/base64url/*.c")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endif()

include_directories( 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${LOCAL_ROOT_PATH}/inc/host_inc
    ${SDK_PATH}/include/CA
    ${LOCAL_ROOT_PATH}/thirdparty/cjson
    ${LOCAL_ROOT_PATH}/thirdparty/libqca
    ${LOCAL_ROOT_PATH}/thirdparty/base64url
    ${LOCAL_ROOT_PATH}/thirdparty/kunpengsecl/verifier
)
add_library(${TARGET} SHARED ${SRC_FILES} ${CJSON_SRC} ${BASE64_SRC})

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(${TARGET} PRIVATE /usr/lib64)
endif()

target_link_libraries(${TARGET} teec_adaptor)

set(LIBRARY_INSTALL ${LOCAL_ROOT_PATH_INSTALL}/usr/lib64)

install(TARGETS ${TARGET} 
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)


