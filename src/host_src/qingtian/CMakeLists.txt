# Copyright (c) IPADS@SJTU 2021. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(qingtian_engine qingtian_0)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/qingtian)

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${CMAKE_BINARY_DIR}/lib)
endif()

include_directories(${LOCAL_ROOT_PATH}/inc/host_inc/qingtian
    ${LOCAL_ROOT_PATH}/inc/common/qingtian)

add_library(${qingtian_engine}  SHARED qingtian_enclave.c host_input.c
            ${CMAKE_SOURCE_DIR}/src/common/qingtian/qt_call.c
            ${CMAKE_SOURCE_DIR}/src/common/qingtian/qt_rpc_proxy.c)

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(${qingtian_engine} PRIVATE
	    ${CMAKE_BINARY_DIR}/lib)
endif()

target_link_libraries(${qingtian_engine}  pthread secgear crypto)

set_target_properties(${qingtian_engine} PROPERTIES SKIP_BUILD_RPATH TRUE)

install(TARGETS ${qingtian_engine}
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)

file(GLOB QT_HOST_HEADERS_1 ${LOCAL_ROOT_PATH}/inc/host_inc/*.h)
file(GLOB QT_HOST_HEADERS_2 ${LOCAL_ROOT_PATH}/inc/host_inc/qingtian/*.h)
file(GLOB QT_HOST_HEADERS_3 ${LOCAL_ROOT_PATH}/inc/host_inc/qingtian/*.edl)

install(FILES ${QT_HOST_HEADERS_1} ${QT_HOST_HEADERS_2} ${QT_HOST_HEADERS_3}
        DESTINATION /usr/include/secGear
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)