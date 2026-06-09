# Copyright (c) 2026 secGear contributors.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
# See the Mulan PSL v2 for more details.

add_executable(secgear_starterkit_host
    main.c
    starterkit_u.c
)

target_include_directories(secgear_starterkit_host PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SECGEAR_INCLUDE_DIR}
    ${SGX_SDK_INCLUDE_DIR}
)

target_link_libraries(secgear_starterkit_host
    ${SECGEAR_LIB}
    /usr/lib64/libsgx_urts.so
    /opt/intel/sgxsdk/lib64/libsgx_uae_service.so
    pthread
)

set_target_properties(secgear_starterkit_host PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
