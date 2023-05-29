 #set sign key
set(PEM Enclave_private.pem)

#set enclave src code
aux_source_directory(. SOURCE_FILES)

#set log level
set(PRINT_LEVEL 3)
add_definitions(-DPRINT_LEVEL=${PRINT_LEVEL})

if(CC_GP)
    #set whilelist. default: /vendor/bin/teec_hello
    set(WHITE_LIST_OWNER root)
    set(WHITE_LIST_0 /vendor/bin/secgear_la)
    set(WHITELIST WHITE_LIST_0)

    #set signed output
    set(OUTPUT ${UUID}.sec)
    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
            --search-path ${SECGEAR_INSTALL_DIR})
endif()

if(CC_SGX)
    #sgxsdk path
    set(OUTPUT ${PREFIX}.signed.so)
    set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c)
    add_custom_command(OUTPUT ${AUTO_FILES}
    DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
    COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
            --search-path ${SECGEAR_INSTALL_DIR}
            --search-path ${SDK_PATH}/include)
endif()

set(COMMON_C_FLAGS "-W -Wall -Werror -fno-short-enums -fno-omit-frame-pointer -fstack-protector \
    -Wstack-protector --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra -nostdinc -nodefaultlibs \
    -fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
    -Wno-error=unused-but-set-variable -Wno-error=format-truncation=")

set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-nostdlib -nodefaultlibs -nostartfiles")

if(CC_GP)
    set(CMAKE_C_FLAGS "${COMMON_C_FLAGS}  -march=armv8-a ")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s -fPIC")
    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-s")

    add_library(${PREFIX} SHARED ${SOURCE_FILES} ${AUTO_FILES})

    target_include_directories(${PREFIX} PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${SECGEAR_INSTALL_DIR}
        ${SDK_PATH}/include/TA
        ${SDK_PATH}/include/TA/huawei_ext
        ${SDK_PATH}/thirdparty/open_source/musl/libc
        ${SDK_PATH}/thirdparty/open_source/musl/libc/arch/aarch64
        ${SDK_PATH}/thirdparty/open_source/musl/libc/arch/generic)

    foreach(WHITE_LIST ${WHITELIST})
         add_definitions(-D${WHITE_LIST}="${${WHITE_LIST}}")
    endforeach(WHITE_LIST)
    add_definitions(-DWHITE_LIST_OWNER="${WHITE_LIST_OWNER}")

    target_link_libraries(${PREFIX} -lsecgear_tee -lsecgear_la)
    add_custom_command(TARGET ${PREFIX}
     	 POST_BUILD
    	         COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt -m ${CMAKE_CURRENT_SOURCE_DIR}/config_cloud.ini -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT})

    install(FILES ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT}
             DESTINATION /data
             PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE  WORLD_READ  WORLD_EXECUTE)
    endif()

if(CC_SGX)
    set(SGX_MODE HW)
    set(CMAKE_C_FLAGS "${COMMON_C_FLAGS} -m64 -fvisibility=hidden -fPIC")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s")

    set(SGX_LIBRARY_PATH ${SDK_PATH}/lib64)

    if(${SGX_MODE} STREQUAL HW)
        set(Trts_Library_Name sgx_trts)
        set(Service_Library_Name sgx_tservice)
    else()
        set(Trts_Library_Name sgx_trts_sim)
        set(Service_Library_Name sgx_tservice_sim)
    endif()

    set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-z,defs -Wl,-pie -Bstatic -Bsymbolic -eenclave_entry \
    -Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/Enclave.lds")

    if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
        link_directories(${SGX_LIBRARY_PATH})
    endif()

    add_library(${PREFIX} SHARED ${SOURCE_FILES} ${AUTO_FILES})

    target_include_directories(${PREFIX} PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        ${SECGEAR_INSTALL_DIR}
        ${SDK_PATH}/include/tlibc
        ${SDK_PATH}/include/libcxx
        ${SDK_PATH}/include)

    if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
        target_link_directories(${PREFIX} PRIVATE
            ${SGX_LIBRARY_PATH} ${SGX_LIBRARY_PATH})
    endif()

    target_link_libraries(${PREFIX} -lsecgear_tee -lsecgear_la -Wl,--whole-archive ${Trts_Library_Name} -Wl,--no-whole-archive
            -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_pthread ${Service_Library_Name} -Wl,--end-group)

    add_custom_command(TARGET ${PREFIX}
     POST_BUILD
     COMMAND umask 0177
     COMMAND openssl genrsa -3 -out ${PEM} 3072
     COMMAND bash ${SIGN_TOOL} -d sign -x sgx -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -k ${PEM} -o ${OUTPUT}
                        -c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml)
endif()
