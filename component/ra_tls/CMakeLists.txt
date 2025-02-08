# Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(ra_tls VERSION 0.1)

set(LIB_NAME ra_tls)
set(LIB_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ra_tls.c)
set(LD_SO cjson curl)
set(HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ra_tls.h ${CMAKE_CURRENT_SOURCE_DIR}/ra_tls_imp.h)
if (NOT TLS_LIB)
set(TLS_LIB OPENSSL)
endif()
if (CMAKE_BUILD_TYPE MATCHES Debug)
add_definitions(-DDEBUG)
endif()
if (TLS_LIB MATCHES OPENSSL)
    add_definitions(-DUSE_OPENSSL)
    set(LD_SO ${LD_SO} crypto ssl)
    set(LIB_SRC ${LIB_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/openssl_imp.c)
else()
    message(FATAL_ERROR "TLS_LIB should defined")
endif()

FILE(GLOB_RECURSE BASE64_SRC CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/base64url/*.c")
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/base64url)

set(LIB_SRC ${LIB_SRC} ${BASE64_SRC})
add_library(${LIB_NAME} SHARED ${LIB_SRC})
target_link_libraries(${LIB_NAME} PUBLIC ${LD_SO})

set_target_properties(${LIB_NAME} PROPERTIES PUBLIC_HEADER "${HEADER_FILES}")
install(TARGETS ${LIB_NAME}
        LIBRARY DESTINATION ${LOCAL_ROOT_PATH_INSTALL}/usr/lib64
        PUBLIC_HEADER DESTINATION ${LOCAL_ROOT_PATH_INSTALL}/usr/include/${LIB_NAME}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)