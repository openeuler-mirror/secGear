# Copyright (c) IPADS@SJTU 2021. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(penglai_engine penglai_0)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/penglai)

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${CMAKE_BINARY_DIR}/lib)
endif()

add_library(${penglai_engine}  SHARED penglai_enclave.c penglai_enclave.h )


target_include_directories(${penglai_engine} PRIVATE
	${PLSDK}/lib/host/include)


if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(${penglai_engine} PRIVATE
	    ${CMAKE_BINARY_DIR}/lib)
endif()


target_link_libraries(${penglai_engine}  pthread secgear ${PLSDK}/lib/libpenglai-enclave-host.a)

set_target_properties(${penglai_engine} PROPERTIES SKIP_BUILD_RPATH TRUE)

install(TARGETS ${penglai_engine}
        LIBRARY
        DESTINATION ${LIBRARY_INSTALL}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ  GROUP_EXECUTE WORLD_READ  WORLD_EXECUTE)
