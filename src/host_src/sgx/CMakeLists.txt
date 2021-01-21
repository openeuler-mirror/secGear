# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(sgx_engine sgx_0)
set(sgxsim_engine sgxsim_0)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/sgx)

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${SGXSDK}/lib64
	    ${CMAKE_BINARY_DIR}/lib)
endif()

add_library(${sgx_engine}  SHARED sgx_enclave.c sgx_enclave.h )
add_library(${sgxsim_engine}  SHARED sgx_enclave.c sgx_enclave.h )

target_include_directories(${sgx_engine} PRIVATE
	${SGXSDK}/include)

target_include_directories(${sgxsim_engine} PRIVATE
	${SGXSDK}/include)

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0") 
    target_link_directories(${sgx_engine} PRIVATE
	    ${SGXSDK}/lib64
	    ${CMAKE_BINARY_DIR}/lib)
endif()

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0") 
    target_link_directories(${sgxsim_engine} PRIVATE
	    ${SGXSDK}/lib64
	    ${CMAKE_BINARY_DIR}/lib)
endif()

target_link_libraries(${sgx_engine}  sgx_urts pthread secgear)
target_link_libraries(${sgxsim_engine}  sgx_urts_sim pthread secgearsim)

set_target_properties(${sgx_engine} PROPERTIES SKIP_BUILD_RPATH TRUE)
set_target_properties(${sgxsim_engine} PROPERTIES SKIP_BUILD_RPATH TRUE)

install(TARGETS ${sgx_engine}
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)

install(TARGETS ${sgxsim_engine}
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
