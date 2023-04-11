# Copyright (c) IPADS@SJTU 2021. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(SOURCE_FILES ${SOURCE_FILES} penglai_seal_data.c  bottom_memory_check.c error_conversion.c penglai_random.c penglai_ocall.c)

set(PENGLAI_MUSL ${SDK_PATH}/musl)
set(SDK_LIB_DIR ${SDK_PATH}/lib)
set(SDK_INCLUDE_DIR ${SDK_LIB_DIR}/app/include)

set(CMAKE_C_FLAGS "${COMMON_C_FLAGS} -fPIC")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")

add_library(${target_lib} STATIC  ${SOURCE_FILES})

target_include_directories(${target_lib} PRIVATE
	${PENGLAI_MUSL}/include
    ${PENGLAI_MUSL}/arch/riscv64
    ${PENGLAI_MUSL}/obj/include
    ${SDK_INCLUDE_DIR}
    ${LOCAL_ROOT_PATH}/inc/enclave_inc/penglai)

install(TARGETS  ${target_lib}
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)

