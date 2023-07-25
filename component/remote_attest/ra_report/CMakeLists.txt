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

set(CMAKE_C_STANDARD 99)
set(TARGET secgear_ra)

set(SRC_FILES sg_ra_report.c)
set(CODEGEN codegen)

if(CC_QT)
    set(PREFIX sg_ra_report)
    set(CODETYPE qingtian)

    # Generate auto files from edl
    set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/sg_ra_report.edl)
    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)

    add_custom_command(OUTPUT ${AUTO_FILES}
        DEPENDS ${EDL_FILE}
        COMMAND ${CODEGEN} --${CODETYPE} --untrusted --header-only ${EDL_FILE} --search-path ${CMAKE_SOURCE_DIR}/inc/host_inc/qingtian)

    List(APPEND SRC_FILES qt_ra_report.c)
    List(APPEND SRC_FILES qtsm_attestation_enclave.c)
endif()


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

include_directories( 
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LOCAL_ROOT_PATH}/inc/host_inc)

add_library(${TARGET} SHARED ${SRC_FILES} ${AUTO_FILES})

install(TARGETS ${TARGET} 
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
