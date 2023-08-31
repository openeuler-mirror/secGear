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
set(PREFIX helloworld)

#set sign tool
set(SIGN_TOOL sign_tool.sh)

#set enclave src code
set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/hello.c)

set(COMMON_C_FLAGS "-W -Wall -Werror -g -fno-short-enums  -fno-omit-frame-pointer -fstack-protector \
    -Wstack-protector --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra \
    -fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
    -Wno-error=unused-but-set-variable -Wno-error=format-truncation=")

set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack")

if(CC_GP)
    #set signed output
    set(OUTPUT ${UUID}.sec)
    #set whilelist. default: /vendor/bin/teec_hello
    set(WHITE_LIST_0 /vendor/bin/secgear_helloworld)
    set(WHITE_LIST_OWNER root)
    set(WHITELIST WHITE_LIST_0)
    foreach(WHITE_LIST ${WHITELIST})
        add_definitions(-D${WHITE_LIST}="${${WHITE_LIST}}")
    endforeach(WHITE_LIST)
    add_definitions(-DWHITE_LIST_OWNER="${WHITE_LIST_OWNER}")
    set(COMMON_C_FLAGS "${COMMON_C_FLAGS} -nostdinc -nodefaultlibs -march=armv8-a")
    set(COMMON_C_LINK_FLAGS "${COMMON_C_LINK_FLAGS} -Wl,-nostdlib -nodefaultlibs -nostartfiles")
    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS}")
    set(ITRUSTEE_LIBC ${SDK_PATH}/thirdparty/open_source/musl/libc)
    set(SDK_INCLUDE
        ${SDK_PATH}/include/TA
        ${SDK_PATH}/include/TA/huawei_ext
        ${ITRUSTEE_LIBC}/arch/aarch64
        ${ITRUSTEE_LIBC}/
        ${ITRUSTEE_LIBC}/arch/arm/bits
        ${ITRUSTEE_LIBC}/arch/generic
        ${ITRUSTEE_LIBC}/arch/arm)
endif()
if(CC_SGX)
    set(OUTPUT enclave.signed.so)
    set(COMMON_C_FLAGS "${COMMON_C_FLAGS} -nostdinc -nodefaultlibs -m64 -fvisibility=hidden")
    set(COMMON_C_LINK_FLAGS "${COMMON_C_LINK_FLAGS} -Wl,-nostdlib -nodefaultlibs -nostartfiles")

    set(LINK_LIBRARY_PATH ${SDK_PATH}/lib64)
    set(Trts_Library_Name sgx_trts)
    set(Service_Library_Name sgx_tservice)
    set(Crypto_Library_Name sgx_tcrypto)

    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-z,defs -Wl,-pie -Bstatic -Bsymbolic -eenclave_entry \
    -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/Enclave.lds")
    set(SDK_INCLUDE
        ${SDK_PATH}/include/tlibc
        ${SDK_PATH}/include/libcxx
        ${SDK_PATH}/include)
endif()
if(CC_QT)
    #set signed output
    set(OUTPUT enclave.eif)
    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS}")
endif()

set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c)
add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
            --search-path /usr/include/secGear --search-path ${SDK_PATH}/include)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -s -fPIC")

add_library(${PREFIX} SHARED ${SOURCE_FILES} ${AUTO_FILES})
target_include_directories(${PREFIX} PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    /usr/include/secGear
    ${SDK_INCLUDE})
if(CC_QT)
    target_link_libraries(${PREFIX} -lsecgear_tee)
    set(ENCLAVE_ENTRY enclave)
    add_executable(${ENCLAVE_ENTRY} enclave.c)
    target_link_directories(${ENCLAVE_ENTRY} PRIVATE ${CMAKE_BINARY_DIR}/lib/)
    target_link_libraries(${ENCLAVE_ENTRY} -lhelloworld -lqtsm)
    target_include_directories(${ENCLAVE_ENTRY} PRIVATE /usr/include/secGear)
    
    set(IMAGE_NAME enclave_image)
    add_custom_command(TARGET ${ENCLAVE_ENTRY}
        POST_BUILD
        COMMAND mkdir -p  ${CMAKE_BINARY_DIR}/eif
        COMMAND cp /usr/lib64/libqtsm.so ${CMAKE_BINARY_DIR}/eif
        COMMAND cp /usr/lib64/libsecgear_tee.a ${CMAKE_BINARY_DIR}/eif
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/libhelloworld.so ${CMAKE_BINARY_DIR}/eif
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/enclave ${CMAKE_BINARY_DIR}/eif
        COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile ${CMAKE_BINARY_DIR}/eif
        COMMAND docker build -t ${IMAGE_NAME} ${CMAKE_BINARY_DIR}/eif
        COMMAND bash ${SIGN_TOOL} -d sign -x qingtian -i ${IMAGE_NAME} -o ${CMAKE_BINARY_DIR}/eif/${OUTPUT}
        )
endif()

if(CC_GP)
    target_link_libraries(${PREFIX} -lsecgear_tee)
    #for trustzone compiling, you should connact us to get config and private_key.pem for test, so we will not sign and install binary in this example #
    add_custom_command(TARGET ${PREFIX}
            POST_BUILD
            COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_CURRENT_BINARY_DIR}/lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt -m ${CMAKE_CURRENT_SOURCE_DIR}/config_cloud.ini -o ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT})

        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT}  
            DESTINATION /data
            PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE  WORLD_READ  WORLD_EXECUTE)

endif()

if(CC_SGX)
    if(${CMAKE_VERSION} VERSION_LESS "3.13.0") 
        link_directories(${LINK_LIBRARY_PATH})
    endif()

    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0") 
        target_link_directories(${PREFIX} PRIVATE
            ${LINK_LIBRARY_PATH})
    endif()

    target_link_libraries(${PREFIX} -lsecgear_tee -Wl,--whole-archive ${Trts_Library_Name} -Wl,--no-whole-archive 
            -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l${Crypto_Library_Name} -l${Service_Library_Name} -Wl,--end-group)

    set(PEM Enclave_private.pem)
    add_custom_command(TARGET ${PREFIX} 
    POST_BUILD
    COMMAND umask 0177
    COMMAND openssl genrsa -3 -out ${PEM} 3072
    COMMAND bash ${SIGN_TOOL} -d sign -x sgx -i ${CMAKE_CURRENT_BINARY_DIR}/lib${PREFIX}.so -k ${PEM} -o ${OUTPUT} -c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml)
endif()

set_target_properties(${PREFIX} PROPERTIES SKIP_BUILD_RPATH TRUE)
