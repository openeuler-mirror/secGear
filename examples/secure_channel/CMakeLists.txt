project(secure_channel C)

set(CMAKE_C_STANDARD 99)

set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(PREFIX sc_demo)

#set edl name
set(EDL_FILE sc_demo.edl)
set(CODEGEN codegen)

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
