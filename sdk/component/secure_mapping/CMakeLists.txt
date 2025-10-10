# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(PREFIX secure_mapping)

set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/secure_mapping.edl)
message(${EDL_FILE})

set(CODEGEN ${LOCAL_ROOT_PATH}/bin/codegen)

set(CODETYPE trustzone)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=default -fPIC")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(target_lib secure_mapping)

set(CMAKE_C_FLAGS "-W -Wall -fno-short-enums -fno-omit-frame-pointer -fstack-protector-strong -Wstack-protector \
                  --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra -nostdinc -nodefaultlibs -fno-peephole \
                  -fno-peephole2 -Wno-main -Wno-error=unused-parameter -Wno-error=unused-but-set-variable \
                  -Wno-error=format-truncation= -D_FORTIFY_SOURCE=2 -O2")
set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-nostdlib -nodefaultlibs -nostartfiles")

set(SOURCE_FILES persistent_object_manager.c mapping_cache.c secure_mapping_enclave.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a -fPIC")
set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-s")
add_definitions(-DGP_ENCLAVE)
set(INCLUDE_DIR ${SDK_PATH}/include/TA
                ${SDK_PATH}/include/TA/huawei_ext
                ${SDK_PATH}/thirdparty/open_source/musl/libc
                ${SDK_PATH}/thirdparty/open_source/musl/libc/arch/aarch64
                ${SDK_PATH}/thirdparty/open_source/musl/libc/arch/generic
                ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee)

add_library(${target_lib} STATIC  ${SOURCE_FILES})

target_include_directories(${target_lib} PRIVATE
    ${LOCAL_ROOT_PATH}/inc/host_inc
    ${INCLUDE_DIR})

install(TARGETS  ${target_lib}
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)

file(GLOB SM_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/secure_mapping_enclave.h
                ${CMAKE_CURRENT_SOURCE_DIR}/mapping_cache.h
                ${CMAKE_CURRENT_SOURCE_DIR}/secure_mapping_host.h
                ${CMAKE_CURRENT_SOURCE_DIR}/secure_mapping.edl)

install(FILES ${SM_HEADERS}
        DESTINATION ${LOCAL_ROOT_PATH_INSTALL}/usr/include/secGear
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)