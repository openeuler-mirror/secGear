# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(CMAKE_C_FLAGS "-W -Wall -fno-short-enums -fno-omit-frame-pointer -fstack-protector-strong -Wstack-protector \
                  --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra -nostdinc -nodefaultlibs -fno-peephole \
                  -fno-peephole2 -Wno-main -Wno-error=unused-parameter -Wno-error=unused-but-set-variable \
                  -Wno-error=format-truncation= -D_FORTIFY_SOURCE=2 -O2")
set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-nostdlib -nodefaultlibs -nostartfiles")
set(SOURCE_FILES ${SOURCE_FILES} ../gp.c ../gp_ocall.c itrustee_seal_data.c error_conversion.c bottom_memory_check.c 
                                 itrustee_random.c itrustee_tswitchless.c itrustee_shared_memory.c  itrustee_tprotected.c)

set(ITRUSTEE_TEEDIR ${iTrusteeSDK}/)
set(ITRUSTEE_LIBC ${iTrusteeSDK}/thirdparty/open_source/musl/libc)

if (CMAKE_COMPILER_IS_GNUCC)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpfullversion -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    string(REGEX MATCHALL "[0-9]+" GCC_VERSION_COMPONENTS ${GCC_VERSION})
    list(GET GCC_VERSION_COMPONENTS 0 GCC_MAJOR)
    list(GET GCC_VERSION_COMPONENTS 1 GCC_MINOR)
    set(GCC_VERSION "${GCC_MAJOR}.${GCC_MINOR}")
endif()

if (GCC_VERSION GREATER_EQUAL "9.4")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a -mno-outline-atomics -fPIC")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a -fPIC")
endif()

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
	${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee
	${ITRUSTEE_TEEDIR}/include/CA
	${LOCAL_ROOT_PATH}/inc/common_inc
	${LOCAL_ROOT_PATH}/inc/common_inc/gp)

install(TARGETS  ${target_lib}
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)

file(GLOB GP_ENCLAVE_HEADERS_1 ${LOCAL_ROOT_PATH}/inc/enclave_inc/*.h)
file(GLOB GP_ENCLAVE_HEADERS_2 ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/*.h)
file(GLOB GP_ENCLAVE_HEADERS_3 ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee/*.h)

install(FILES ${GP_ENCLAVE_HEADERS_1} ${GP_ENCLAVE_HEADERS_2} ${GP_ENCLAVE_HEADERS_3}
        DESTINATION /usr/include/secGear
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
