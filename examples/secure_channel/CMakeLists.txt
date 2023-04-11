cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(secure_channel C)

set(CMAKE_C_STANDARD 99)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(PREFIX sc_demo)

if (NOT DEFINED ENCLAVE)
set(ENCLAVE "SGX")
endif()
set(SGX_SDK_DEFAULT_PATH /opt/intel/sgxsdk)
set(GP_SDK_DEFAULT_PATH /opt/itrustee_sdk)
set(PL_SDK_DEFAULT_PATH /root/dev/sdk)

if (NOT DEFINED SSL_PATH)
set(SSL_PATH /opt/intel/sgxssl)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(${ENCLAVE} STREQUAL "GP")
if (NOT DEFINED SDK_PATH)
set(iTrusteeSDK ${GP_SDK_DEFAULT_PATH})
else()
set(iTrusteeSDK ${SDK_PATH})
endif()
message("Current Platform: ARM Trustzone, iTrustee SDK PATH:${iTrusteeSDK}")
if(NOT IS_DIRECTORY ${iTrusteeSDK})
message(FATAL_ERROR "Please provide the correct iTrusteeSDK path")
endif()
set(CC_GP ON)
endif()

if(${ENCLAVE} STREQUAL "SGX")
if (NOT DEFINED SDK_PATH)
set(SGXSDK ${SGX_SDK_DEFAULT_PATH})
else()
set(SGXSDK ${SDK_PATH})
endif()
message("Current Platform: Intel SGX, SGX SDK PATH:${SGXSDK}")
if(NOT IS_DIRECTORY ${SGXSDK})
message(FATAL_ERROR "Please provide the correct SGXSDK path")
endif()
set(CC_SGX ON)
endif()

#set edl name
set(EDL_FILE sc_demo.edl)
set(CODEGEN codegen)
set(SIGN_TOOL sign_tool.sh)

set(SECGEAR_INSTALL_DIR /usr/include/secGear)

if(CC_GP)
    set(CODETYPE trustzone)
    set(UUID 7763a15a-0a9e-4e86-90cd-e4262583948a)
    add_definitions(-DPATH="/data/${UUID}.sec")
endif()

if(CC_SGX)
    set(CODETYPE sgx)
    add_definitions(-DPATH="${CMAKE_CURRENT_BINARY_DIR}/enclave/${PREFIX}.signed.so")
endif()

add_subdirectory(${CURRENT_ROOT_PATH}/enclave)
add_subdirectory(${CURRENT_ROOT_PATH}/host)
add_subdirectory(${CURRENT_ROOT_PATH}/client)
add_subdirectory(${CURRENT_ROOT_PATH}/client_with_recv_thread)
