# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#set auto code prefix
set(PREFIX switchless)
#set host exec name
set(OUTPUT secgear_switchless)
#set host src code
set(SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

#set auto code
if(CC_GP)
    set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h
                   ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c
                   ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)
    add_custom_command(OUTPUT ${AUTO_FILES}
                       DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
                       COMMAND ${CODEGEN} --${CODETYPE}
                                          --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
                                          --search-path ${SECGEAR_INSTALL_DIR})
endif()

if(CC_SGX)
    set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c)
    add_custom_command(OUTPUT ${AUTO_FILES}
                       DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
                       COMMAND ${CODEGEN} --${CODETYPE}
                                          --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
                                          --search-path ${SECGEAR_INSTALL_DIR}
                                          --search-path ${SDK_PATH}/include)
endif()

if(CC_PL)
    message(FATAL_ERROR "The PL platform does not support switchless.")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -s")

if(CC_GP)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE ${CMAKE_BINARY_DIR}/inc
                                                 ${SECGEAR_INSTALL_DIR}/
                                                 ${CMAKE_CURRENT_BINARY_DIR})
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
endif()

if(CC_SGX)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif()
    add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
    target_include_directories(${OUTPUT} PRIVATE ${SECGEAR_INSTALL_DIR}/
                                                 ${SDK_PATH}/include
                                                 ${CMAKE_CURRENT_BINARY_DIR})
    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SDK_PATH}/lib64)
    endif()
endif()

if(CC_PL)
    message(FATAL_ERROR "The PL platform does not support switchless.")
endif()

if(CC_SIM)
    target_link_libraries(${OUTPUT} secgearsim pthread)
else()
    if(CC_GP)
        target_link_libraries(${OUTPUT} secgear pthread)
    endif()
    if(CC_SGX)
        target_link_libraries(${OUTPUT} secgear pthread -Wl,--whole-archive -lsgx_uswitchless -Wl,--no-whole-archive -lsgx_urts)
    endif()
endif()
set_target_properties(${OUTPUT} PROPERTIES SKIP_BUILD_RPATH TRUE)

if(CC_GP)
    install(TARGETS ${OUTPUT}
            RUNTIME
            DESTINATION /vendor/bin/
       	    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
		        GROUP_EXECUTE GROUP_READ
		        WORLD_EXECUTE WORLD_READ)  
endif()

if(CC_SGX)
    install(TARGETS ${OUTPUT}
            RUNTIME
            DESTINATION ${CMAKE_BINARY_DIR}/bin/
       	    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
		        GROUP_EXECUTE GROUP_READ
		        WORLD_EXECUTE WORLD_READ)  
endif()

if(CC_PL)
    message(FATAL_ERROR "The PL platform does not support switchless.")
endif()

