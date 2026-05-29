# Copyright (c) 2026 secGear contributors.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND.
# See the Mulan PSL v2 for more details.

set(ENCLAVE_NAME enclave)
set(ENCLAVE_SIGNED ${CMAKE_BINARY_DIR}/enclave.signed.so)

add_library(${ENCLAVE_NAME} SHARED
    enclave.c
    starterkit_t.c
)

target_include_directories(${ENCLAVE_NAME} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SGX_SDK_INCLUDE_DIR}
    ${SGX_SDK_INCLUDE_DIR}/tlibc
    ${SGX_SDK_INCLUDE_DIR}/libcxx
    ${SECGEAR_INCLUDE_DIR}
)

target_compile_options(${ENCLAVE_NAME} PRIVATE
    -m64
    -O2
    -fPIC
    -fvisibility=hidden
    -Wno-attributes
)

target_link_directories(${ENCLAVE_NAME} PRIVATE
    ${SGX_SDK_LIB_DIR}
)

target_link_options(${ENCLAVE_NAME} PRIVATE
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    -Wl,-z,defs
    -Wl,-z,now
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,-pie
    -Wl,-Bstatic
    -Wl,-Bsymbolic
    -Wl,-eenclave_entry
    -Wl,--export-dynamic
    -Wl,--defsym,__ImageBase=0
    -Wl,--gc-sections
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/Enclave.lds
)

target_link_libraries(${ENCLAVE_NAME}
    -Wl,--whole-archive sgx_trts -Wl,--no-whole-archive
    -Wl,--start-group
    sgx_tstdc
    sgx_tcxx
    sgx_tcrypto
    sgx_tservice
    -Wl,--end-group
)

add_custom_command(
    TARGET ${ENCLAVE_NAME}
    POST_BUILD
    COMMAND umask 0177
    COMMAND openssl genrsa -3 -out ${CMAKE_CURRENT_BINARY_DIR}/Enclave_private.pem 3072
    COMMAND /opt/intel/sgxsdk/bin/x64/sgx_sign sign
            -key ${CMAKE_CURRENT_BINARY_DIR}/Enclave_private.pem
            -enclave ${CMAKE_CURRENT_BINARY_DIR}/lib${ENCLAVE_NAME}.so
            -out ${ENCLAVE_SIGNED}
            -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml
    VERBATIM
)
