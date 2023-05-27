# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(secgear_ra C)

set(TARGET secgear_ra)

set(SRC_FILES sg_ra_report.c)
if(CC_SGX)
    set(SRC_FILES ${SRC_FILES} sgx_ra_report.c)
endif()

if(CC_GP)
    aux_source_directory(${LOCAL_ROOT_PATH}/thirdparty/cjson/ CJSON_SRC)
    FILE (GLOB_RECURSE BASE64_SRC "${LOCAL_ROOT_PATH}/thirdparty/base64url/*.c")
    set(SRC_FILES ${SRC_FILES} ${CJSON_SRC} ${BASE64_SRC} gp_ra_report.c)
    set(INCLUDE_DIR ${SDK_PATH}/include/CA
                    ${LOCAL_ROOT_PATH}/thirdparty/cjson
                    ${LOCAL_ROOT_PATH}/thirdparty/libqca
                    ${LOCAL_ROOT_PATH}/thirdparty/base64url)
    set(LINK_LIB teec_adaptor)
endif()


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

include_directories( 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${LOCAL_ROOT_PATH}/inc/host_inc
    ${INCLUDE_DIR})
add_library(${TARGET} SHARED ${SRC_FILES})


target_link_libraries(${TARGET} ${LINK_LIB})

install(TARGETS ${TARGET} 
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)


