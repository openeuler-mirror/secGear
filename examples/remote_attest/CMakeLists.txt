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
project(qca_demo C)

set(TARGET qca_demo)

set(SECGEAR_INSTALL_DIR /usr/include/secGear)

aux_source_directory(. SRC_FILES)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -g")

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(/usr/lib64)
endif()

include_directories( 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SECGEAR_INSTALL_DIR})

add_executable(${TARGET} ${SRC_FILES})

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(${TARGET} PRIVATE /usr/lib64)
endif()

target_link_libraries(${TARGET} secgear secgear_ra secgear_verify crypto qca teeverifier)

set(LIBRARY_INSTALL .)

install(TARGETS ${TARGET} 
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)


