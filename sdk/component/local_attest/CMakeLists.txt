# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
set(target_lib secgear_la)

set(CMAKE_C_FLAGS "-W -Wall -fno-short-enums -fno-omit-frame-pointer -fstack-protector-strong -Wstack-protector \
                  --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra -nostdinc -nodefaultlibs -fno-peephole \
                  -fno-peephole2 -Wno-main -Wno-error=unused-parameter -Wno-error=unused-but-set-variable \
                  -Wno-error=format-truncation= -D_FORTIFY_SOURCE=2 -O2")
set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-nostdlib -nodefaultlibs -nostartfiles")

set(SOURCE_FILES sg_local_attest.c)

if(CC_SGX)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")
    add_definitions(-DSGX_ENCLAVE)
    set(SOURCE_FILES ${SOURCE_FILES} sgx_local_attest.c)
endif()

if(CC_GP)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8-a -fPIC")
    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-s")
    add_definitions(-DGP_ENCLAVE)
    aux_source_directory(${LOCAL_ROOT_PATH}/thirdparty/cjson/ CJSON_SRC)
    FILE (GLOB_RECURSE BASE64_SRC "${LOCAL_ROOT_PATH}/thirdparty/base64url/*.c")
    set(REPORT_HELPER ${LOCAL_ROOT_PATH}/component/remote_attest/ra_report/gp_report_helper.c)
    set(SOURCE_FILES ${SOURCE_FILES} gp_local_attest.c ${CJSON_SRC} ${BASE64_SRC} ${REPORT_HELPER})
    set(INCLUDE_DIR ${SDK_PATH}/include/TA
                    ${SDK_PATH}/include/TA/huawei_ext
                    ${SDK_PATH}/thirdparty/open_source/musl/libc
                    ${SDK_PATH}/thirdparty/open_source/musl/libc/arch/aarch64
                    ${SDK_PATH}/thirdparty/open_source/musl/libc/arch/generic
                    ${LOCAL_ROOT_PATH}/thirdparty/cjson
                    ${LOCAL_ROOT_PATH}/thirdparty/base64url
                    ${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee)
endif()

add_library(${target_lib} STATIC  ${SOURCE_FILES})

target_include_directories(${target_lib} PRIVATE
    ${LOCAL_ROOT_PATH}/inc/host_inc
    ${LOCAL_ROOT_PATH}/component/remote_attest
    ${LOCAL_ROOT_PATH}/component/remote_attest/ra_report
    ${INCLUDE_DIR})

install(TARGETS  ${target_lib}
        ARCHIVE
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)

file(GLOB LA_HEADERS sg_local_attest.h)
install(FILES ${LA_HEADERS}
        DESTINATION /usr/include/secGear
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
