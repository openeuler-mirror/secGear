# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden -fPIC -Wno-stringop-overflow")

set(LIBRARY_INSTALL /usr/lib64)

include_directories(${LOCAL_ROOT_PATH}/inc/host_inc)

if(CC_GP)
    add_subdirectory(gp)
endif()

if(CC_SGX)
    add_subdirectory(sgx)
endif()

add_library(secgear SHARED enclave.c enclave_internal.c ocall_log.c enclave_ocall.c)
add_library(secgearsim SHARED enclave.c enclave_internal.c ocall_log.c enclave_ocall.c)

target_link_libraries(secgear dl pthread)
target_link_libraries(secgearsim dl pthread)

set_target_properties(secgear PROPERTIES 
            SKIP_BUILD_RPATH TRUE)

target_compile_definitions(secgearsim PRIVATE CC_SIM)
set_target_properties(secgearsim PROPERTIES 
            SKIP_BUILD_RPATH TRUE)

install(TARGETS  secgear
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
install(TARGETS  secgearsim
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS  OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
