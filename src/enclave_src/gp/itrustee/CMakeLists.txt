# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(SOURCE_FILES ${SOURCE_FILES} ../gp.c ../gp_ocall.c itrustee_seal_data.c error_conversion.c bottom_memory_check.c itrustee_random.c)

set(ITRUSTEE_TEEDIR ${iTrusteeSDK}/)
set(ITRUSTEE_LIBC ${iTrusteeSDK}/thirdparty/open_source/musl/libc)
set(CMAKE_C_FLAGS "${COMMON_C_FLAGS}  -march=armv8-a -fPIC")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")

add_library(${target_lib} STATIC  ${SOURCE_FILES})

target_include_directories(${target_lib} PRIVATE
	${ITRUSTEE_TEEDIR}/include/TA
	${ITRUSTEE_TEEDIR}/include/TA/huawei_ext
	${ITRUSTEE_LIBC}/arch/aarch64
	${ITRUSTEE_LIBC}/
	${ITRUSTEE_LIBC}/arch/arm/bits
	${ITRUSTEE_LIBC}/arch/generic
	${ITRUSTEE_LIBC}/arch/arm
	${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/
	${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee)

install(TARGETS  ${target_lib}
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
