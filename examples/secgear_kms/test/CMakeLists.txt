# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

project(secGearKMS CXX)

set(CMAKE_CXX_STANDARD 11)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(OUTPUT secgear_kms_test)

Include(FetchContent)

FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.0.1 # or a later release
)

FetchContent_MakeAvailable(Catch2)

find_package(OpenSSL REQUIRED)

add_executable(${OUTPUT} test.cpp)
target_include_directories(${OUTPUT} PRIVATE
        ${CURRENT_ROOT_PATH}/../include)

if (CC_GP)
    if (${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif ()
    if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
    endif ()
    target_link_libraries(${OUTPUT} secgear pthread qca Catch2::Catch2WithMain OpenSSL::SSL OpenSSL::Crypto secgear_kms)
endif ()

if (CC_SGX)
    if (${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SDK_PATH}/lib64 ${SSL_PATH}/lib64)
    endif ()
    if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${OUTPUT} PRIVATE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${SDK_PATH}/lib64 ${SSL_PATH}/lib64)
    endif ()
    target_link_libraries(${OUTPUT} secgear pthread sgx_usgxssl Catch2::Catch2WithMain OpenSSL::SSL OpenSSL::Crypto secgear_kms)
endif ()

if (CC_GP)
    install(TARGETS ${OUTPUT}
            RUNTIME
            DESTINATION /vendor/bin/
            PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
    set_target_properties(${OUTPUT} PROPERTIES INSTALL_RPATH ${CMAKE_BINARY_DIR}/lib)
endif ()

if (CC_SGX)
    install(TARGETS ${OUTPUT}
            RUNTIME
            DESTINATION ${CMAKE_BINARY_DIR}/bin/
            PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
    set_target_properties(${OUTPUT} PROPERTIES INSTALL_RPATH ${CMAKE_BINARY_DIR}/lib)
endif ()