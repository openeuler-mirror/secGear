cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(local_attest C)

set(CMAKE_C_STANDARD 99)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(PREFIX la_demo)

if (NOT DEFINED ENCLAVE)
set(ENCLAVE "SGX")
endif()
set(SGX_SDK_DEFAULT_PATH /opt/intel/sgxsdk)
set(GP_SDK_DEFAULT_PATH /opt/itrustee_sdk)

if (NOT DEFINED SSL_PATH)
set(SSL_PATH /opt/intel/sgxssl)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(${ENCLAVE} STREQUAL "GP")
    if (NOT DEFINED SDK_PATH)
        set(SDK_PATH ${GP_SDK_DEFAULT_PATH})
    endif()
    if(NOT IS_DIRECTORY ${SDK_PATH})
        message(FATAL_ERROR "Please provide the correct SDK_PATH path")
    endif()
    set(CC_GP ON)
endif()

if(${ENCLAVE} STREQUAL "SGX")
    if (NOT DEFINED SDK_PATH)
        set(SDK_PATH ${SGX_SDK_DEFAULT_PATH})
    endif()
    if(NOT IS_DIRECTORY ${SDK_PATH})
        message(FATAL_ERROR "Please provide the correct SDK_PATH path")
    endif()
    set(CC_SGX ON)
endif()

#set edl name
set(EDL_FILE la_demo.edl)
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
