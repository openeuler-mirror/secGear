# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#set host exec name
set(OUTPUT secgear_tls)
#set host src code
set(SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

#set auto code
if(CC_SGX)
    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/sgx  --search-path ${SGXSDK}/include --search-path ${ENCLAVE_SSL}/include)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s")

if(CC_SGX)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SGXSSL}/lib64)
    endif()
    set(SGX_MODE HW)
    if(${SGX_MODE} STREQUAL HW)
        set(Urts_Library_Name sgx_urts)
    else()
        set(Urts_Library_Name sgx_urts_sim)
    endif()
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE
			${LOCAL_ROOT_PATH}/inc/host_inc 
			${LOCAL_ROOT_PATH}/inc/host_inc/sgx
            ${CMAKE_CURRENT_BINARY_DIR})
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
	    target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${ENCLAVE_SSL}/lib64)
    endif()
    target_link_libraries(${OUTPUT} secgear ${Urts_Library_Name} pthread ssl crypto sgx_usgxssl)
endif()

set_target_properties(${OUTPUT} PROPERTIES SKIP_BUILD_RPATH TRUE)

if(CC_SGX)
	install(TARGETS  ${OUTPUT}
        	RUNTIME
        	DESTINATION ${CMAKE_BINARY_DIR}/bin/
       	 	PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)  
endif()
	
