# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(secure_channel_client C)

set(PREFIX secure_channel)
set(SOURCE_FILE secure_channel_client.c ${CMAKE_CURRENT_SOURCE_DIR}/../secure_channel_common.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endif()

include_directories( 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOCAL_ROOT_PATH}/inc/host_inc
    ${LOCAL_ROOT_PATH}/component/secure_channel
)
add_library(c${PREFIX} SHARED ${SOURCE_FILE})

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(c${PREFIX} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endif()

target_link_libraries(c${PREFIX} ssl crypto)

set(LIBRARY_INSTALL ${LOCAL_ROOT_PATH_INSTALL}/usr/lib64)

install(TARGETS c${PREFIX} 
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)


