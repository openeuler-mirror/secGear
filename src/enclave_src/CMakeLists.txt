# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(secgear_tee C)

set(target_lib secgear_tee)
set(LIBRARY_INSTALL /usr/lib64)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/secgear_seal_data.c ${CMAKE_CURRENT_SOURCE_DIR}/memory_check.c ${CMAKE_CURRENT_SOURCE_DIR}/secgear_random.c)
#head file path
include_directories(${LOCAL_ROOT_PATH}/inc/host_inc
	${LOCAL_ROOT_PATH}/inc/enclave_inc)

set(COMMON_C_FLAGS "-D_FORTIFY_SOURCE=2 -O2 -ftrapv -fstack-protector-all  -fno-short-enums  -fno-omit-frame-pointer \
         --param ssp-buffer-size=4 -frecord-gcc-switches -nostdinc -nodefaultlibs \
        -fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
        -Wno-error=unused-but-set-variable -Wno-error=format-truncation=")


if(CC_GP)
	add_subdirectory(gp/itrustee)
endif()

if(CC_SGX)
	add_subdirectory(sgx)
endif()
