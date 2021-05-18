# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(gp_engine gp_0)

# to do itrustee sdk Open Source
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/gp)

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${CMAKE_BINARY_DIR}/lib)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=implicit-function-declaration")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}")

add_library(${gp_engine}  SHARED gp_enclave.h gp_enclave.c)

target_include_directories(${gp_engine} PRIVATE
	${iTrusteeSDK}/include/CA)
	
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0") 
    target_link_directories(${gp_engine} PRIVATE ${CMAKE_BINARY_DIR}/lib)
endif()

set_target_properties(${gp_engine} PROPERTIES SKIP_BUILD_RPATH TRUE)
#link iTrustee teec lib
target_link_libraries(${gp_engine} secgear pthread teec_adaptor)

install(TARGETS ${gp_engine}
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
