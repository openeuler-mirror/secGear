# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

set(OUTPUT tls_client)
set(SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/tls_client.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s")

if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
    link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endif()
    
add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
    target_link_directories(${OUTPUT} PRIVATE 
	    ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endif()

target_link_libraries(${OUTPUT} ssl crypto)

set_target_properties(${OUTPUT} PROPERTIES SKIP_BUILD_RPATH TRUE)

if(CC_SGX)
	install(TARGETS  ${OUTPUT}
        	RUNTIME
        	DESTINATION ${CMAKE_BINARY_DIR}/bin/
       	 	PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)  
endif()
	
