# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(SOURCE_FILES ${SOURCE_FILES} sgx_seal_data.c  bottom_memory_check.c error_conversion.c sgx_random.c)

set(SGX_DIR ${SGXSDK})

set(CMAKE_C_FLAGS "${COMMON_C_FLAGS} -m64 -fPIC")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")

add_library(${target_lib} STATIC  ${SOURCE_FILES})

target_include_directories(${target_lib} PRIVATE
	${SGX_DIR}/include/tlibc
    ${SGX_DIR}/include
    ${LOCAL_ROOT_PATH}/inc/enclave_inc/sgx)

install(TARGETS  ${target_lib}
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)

