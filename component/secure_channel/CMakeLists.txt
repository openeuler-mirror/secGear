# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(PREFIX secure_channel)

set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/secure_channel.edl)
message(${EDL_FILE})

set(CODEGEN codegen)

if(CC_GP)
    set(CODETYPE trustzone)
else()
    set(CODETYPE sgx)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=default -fPIC")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

ADD_SUBDIRECTORY(enclave)
ADD_SUBDIRECTORY(host)
ADD_SUBDIRECTORY(client)

file(GLOB SEC_CHL_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/client/secure_channel_client.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/host/secure_channel_host.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/enclave/secure_channel_enclave.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/secure_channel.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/secure_channel.edl)

install(FILES ${SEC_CHL_HEADERS}
        DESTINATION /usr/include/secGear
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
