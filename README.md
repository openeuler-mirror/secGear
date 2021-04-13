<img src="docs/logo.png" alt="secGear" style="zoom:100%;" />

secGear
============================

介绍
-----------

SecGear则是面向计算产业的机密计算安全应用开发套件。旨在方便开发者在不同的硬件设备上提供统一开发框架。目前secGear支持intel SGX硬件和Trustzone itrustee。

构建、安装
----------------

- [详见 构建、安装](./docs/build_install.md)

开发应用和编译
------------------------------

开发目录 .../secGear/examples/test/

### 1 编写edl接口文件

	enclave {
		include "secgear_urts.h"
		from "secgear_tstdc.edl" import *;
		trusted {
			public int get_string([out, size=32]char *buf);
		};
	};
'include "secgear_urts.h" from "secgear_tstdc.edl" import *'是为了屏蔽SGX和iTrustee在调用libc库之间的差异。所以为了开发代码的一致性，默认导入这两个文件。
有关edl语法的详细信息，请参阅SGX开发文档定义的EDL(Enclave Definition Language)语法部分。
目前SGX和iTrustee在基本类型、指针类型和深拷贝方面是相互兼容的。对于user_check、private ecalls、switchless特性仅支持sgx硬件。

保存文件名为test.edl

### 2 编写最外层CMakeLists.txt文件

	cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
	project(TEST  C)
	set(CMAKE_C_STANDARD 99)
	set(CURRENT_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})
	set(EDL_FILE test.edl)
	set(LOCAL_ROOT_PATH "$ENV{CC_SDK}")
        set(SECGEAR_INSTALL_PATH /lib64/)
	set(CODEGEN codegen)
	if(CC_GP)
		set(CODETYPE trustzone)
		execute_process(COMMAND uuidgen -r OUTPUT_VARIABLE UUID)
		string(REPLACE "\n" "" UUID ${UUID})
		add_definitions(-DPATH="/data/${UUID}.sec")
	endif()
	if(CC_SGX)
		set(CODETYPE sgx)
		add_definitions(-DPATH="${CMAKE_CURRENT_BINARY_DIR}/enclave/enclave.signed.so")
	endif()
	add_subdirectory(${CURRENT_ROOT_PATH}/enclave)
	add_subdirectory(${CURRENT_ROOT_PATH}/host)

EDL_FILE、CODETYPE：稍后自动构建的时候会用到这些属性。
UUID：在iTrustee中，构建安全enclave动态库需要使用UUID命名，这里由uuidgen命令自动生成。
DPATH：用于定义非安全侧使用安全侧动态库的绝对路径

### 3 编写非安全侧代码和CMakeLists.txt文件

#### 3.1 创建host目录和main.c文件

	#include <stdio.h>
	#include "enclave.h"
	#include "test_u.h"

	#define BUF_LEN 32

	int main()
	{
		int  retval = 0;
		char *path = PATH;
		char buf[BUF_LEN];
		cc_enclave_t *context = NULL;
		cc_enclave_result_t res;
		
		res = cc_enclave_create(path, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, &context);
		...

		res = get_string(context, &retval, buf);
		if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
			printf("Ecall enclave error\n");
		} else {
			printf("%s\n", buf);
		}

		if (context != NULL) {
			res = cc_enclave_destroy(context);
			...
		}
		return res;
	}

enclave.h: secGear库头文件
test_u.h: 根据edl文件自动生成的非安全侧头文件。
cc_enclave_create: 用于创建enclave安全上下文。
get_string: 根据edl中trusted定义的安全侧代理函数，该代理函数用于进入到安全侧执行安全代码。
cc_enclave_destroy: 用于销毁enclave安全上下文。

注意：这里调用的get_string函数与在edl中定义的get_string函数有些不同，这里的参数比edl中定义的多了前两个参数，分别是enclave安全上下文
和retval参数。这是因为codegen（自动生成代码工具）通过edl生成的非安全侧代理函数，其声明在test_u.h中。
如果在edl中定义的函数无返回值时，例如"public void get_string([out,size=32] char *buf);"则非安全侧代理函数为
"res=get_string(context, buf)"(这里就不在有retval参数)

#### 3.2 编写非安全侧CMakeLists.txt

        #set auto code prefix
	set(PREFIX test)
	#set host exec name
	set(OUTPUT secgear_test)
	#set host src code
	set(SOURCE_FILE ${CMAKE_CURRENT_SOURCE_DIR}/main.c)    

设置预备的基础变量

        #set auto code
	if(CC_GP)
		set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)
		add_custom_command(OUTPUT ${AUTO_FILES}
		DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
		COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/gp)
	endif()

	if(CC_SGX)
		set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c)
		add_custom_command(OUTPUT ${AUTO_FILES}
		DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
		COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/sgx  --search-path ${SGXSDK}/include)
	endif()

设置使用代码辅助生成工具根据edl文件生成辅助代码。CODEGEN和CODETYPE等变量定义在CMakeList.txt文件.--search-path用于搜索在edl文件中导入依赖的其他edl文件。
当使用SGX时，需要导入sgx提供的基础edl，因此这里指定了SGXSDK的patch "--search-path ${SGXSDK}/include)"。

	set(CMAKE_C_FLAGS "-fstack-protector-all -W -Wall -Werror -Wextra -Werror=array-bounds -D_FORTIFY_SOURCE=2 -O2 -ftrapv -fPIE")
	set(CMAKE_EXE_LINKER_FLAGS    "-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack")

设置编译选项和链接选项

	if(CC_GP)
		if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
			link_directories(${SECGEAR_INSTALL_PATH})
		endif()
		add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
		target_include_directories(${OUTPUT} PRIVATE
						${LOCAL_ROOT_PATH}/inc/host_inc
						${LOCAL_ROOT_PATH}/inc/host_inc/gp
						${CMAKE_CURRENT_BINARY_DIR})
		if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
			target_link_directories(${OUTPUT} PRIVATE ${SECGEAR_INSTALL_PATH})
		endif()
	endif()

在iTrustee硬件环境上，设置头文件的搜索路径及编译生成非安全侧二进制文件。

	if(CC_SGX)
		if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
			link_directories(${SECGEAR_INSTALL_PATH})
		endif()
		add_executable(${OUTPUT} ${SOURCE_FILE} ${AUTO_FILES})
		target_include_directories(${OUTPUT} PRIVATE
							${LOCAL_ROOT_PATH}/inc/host_inc
							${LOCAL_ROOT_PATH}/inc/host_inc/sgx
							${CMAKE_CURRENT_BINARY_DIR})
		if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
			target_link_directories(${OUTPUT} PRIVATE ${SECGEAR_INSTALL_PATH})
		endif()
	endif()

在SGX硬件环境上，设置头文件的搜索路径及编译生成非安全侧二进制文件。

	if(CC_SIM)
            target_link_libraries(${OUTPUT} secgearsim)
        else()
            target_link_libraries(${OUTPUT} secgear)
        endif()
        set_target_properties(${OUTPUT} PROPERTIES SKIP_BUILD_RPATH TRUE)
	if(CC_GP)
		install(TARGETS  ${OUTPUT}
				RUNTIME
				DESTINATION /vendor/bin/
				PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
	endif()
	if(CC_SGX)
		install(TARGETS  ${OUTPUT}
				RUNTIME
				DESTINATION ${CMAKE_BINARY_DIR}/bin/
				PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ)
	endif()


设置secGear链接库，当指定模拟模式CC_SIM时链接libsecgearsim.so，否则链接libsecgear.so。
在iTrustee硬件环境上需指定安装固定的安全白名单。

### 4 编写安全侧代码、CMakeList.txt及基础配置文件

#### 4.1 创建enclave目录 编写hello.c

	#include <stdio.h>
	#include <string.h>
	#include "test_t.h"

	#define TA_HELLO_WORLD        "secGear hello world!"
	#define BUF_MAX 32
	int get_string(char *buf)
	{
		strncpy(buf, TA_HELLO_WORLD, strlen(TA_HELLO_WORLD) + 1);
		return 0;
	}

test_t.h：该头文件为自动生成代码工具codegen通过edl文件生成的头文件。该头文件命名为edl文件名加"_t"。

#### 4.2 编写CMakeList.txt文件

	#set auto code prefix
	set(PREFIX test)
	#set sign key
	set(PEM Enclave_private.pem)

设置enclave签名私钥

	#set sign tool
	set(SIGN_TOOL ${LOCAL_ROOT_PATH}/tools/sign_tool/sign_tool.sh)
	#set enclave src code
	set(SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/hello.c)
	#set log level
	set(PRINT_LEVEL 3)
	add_definitions(-DPRINT_LEVEL=${PRINT_LEVEL})

设置签名工具已经安全侧打印日志level

	if(CC_GP)
            #set signed output
            set(OUTPUT ${UUID}.sec)

            set(WHITE_LIST_0 /vendor/bin/helloworld)
            set(WHITE_LIST_1 /vendor/bin/secgear_test)
            set(WHITE_LIST_OWNER root)
            set(WHITELIST WHITE_LIST_0 WHITE_LIST_1)

            set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_args.h)
            add_custom_command(OUTPUT ${AUTO_FILES}
            DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
            COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/gp)
	endif()

WHITE_LIST_x：为设置iTrustee的二进制白名单，只有这里定义的白名单，在非安全侧的二进制才可以调用安全侧的动态库。上限为8个。
WHITE_LIST_OWNER：为设置运行二进制的用户，只有该用户才可以调用安全侧动态库。
AUTO_FILES：由edl文件生成的安全侧二进制文件

        if(CC_SGX)
	        set(OUTPUT enclave.signed.so)
	        set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_t.c)
	        add_custom_command(OUTPUT ${AUTO_FILES}
	        DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
	        COMMAND ${CODEGEN} --${CODETYPE} --trusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/sgx --search-path ${SGXSDK}/include)
	endif()

设置自动生成代码及签名动态库。

	set(COMMON_C_FLAGS "-W -Wall -Werror  -fno-short-enums  -fno-omit-frame-pointer -fstack-protector \
			-Wstack-protector --param ssp-buffer-size=4 -frecord-gcc-switches -Wextra -nostdinc -nodefaultlibs \
			-fno-peephole -fno-peephole2 -Wno-main -Wno-error=unused-parameter \
			-Wno-error=unused-but-set-variable -Wno-error=format-truncation=")

	set(COMMON_C_LINK_FLAGS "-Wl,-z,now -Wl,-z,relro -Wl,-z,noexecstack -Wl,-nostdlib -nodefaultlibs -nostartfiles")

设置安全侧便编译选项和链接选项。由于安全侧和非安全侧不同，非安全侧的标准动态库不能被安全侧链接。例如："-nostdlib -nodefaultlibs -nostartfiles"


	if(CC_GP)
		configure_file("${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt.in" "${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt")

		set(CMAKE_C_FLAGS "${COMMON_C_FLAGS}  -march=armv8-a ")
		set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s -fPIC")
		set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-s")

		set(ITRUSTEE_TEEDIR ${iTrusteeSDK}/)
		set(ITRUSTEE_LIBC ${iTrusteeSDK}/thirdparty/open_source/musl/libc)

		if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
			link_directories(${SECGEAR_INSTALL_PATH})
		endif()

		add_library(${PREFIX} SHARED ${SOURCE_FILES} ${AUTO_FILES})

		target_include_directories( ${PREFIX} PRIVATE
			${CMAKE_CURRENT_BINARY_DIR}
			${LOCAL_ROOT_PATH}/inc/host_inc
			${LOCAL_ROOT_PATH}/inc/host_inc/gp
			${LOCAL_ROOT_PATH}/inc/enclave_inc
			${LOCAL_ROOT_PATH}/inc/enclave_inc/gp
			${ITRUSTEE_TEEDIR}/include/TA
			${ITRUSTEE_TEEDIR}/include/TA/huawei_ext
			${ITRUSTEE_LIBC}/arch/aarch64
			${ITRUSTEE_LIBC}/
			${ITRUSTEE_LIBC}/arch/arm/bits
			${ITRUSTEE_LIBC}/arch/generic
			${ITRUSTEE_LIBC}/arch/arm
			${LOCAL_ROOT_PATH}/inc/enclave_inc/gp/itrustee)

		if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
			target_link_directories(${PREFIX} PRIVATE ${SECGEAR_INSTALL_PATH})
		endif()

		foreach(WHITE_LIST ${WHITELIST})
			add_definitions(-D${WHITE_LIST}="${${WHITE_LIST}}")
		endforeach(WHITE_LIST)
		add_definitions(-DWHITE_LIST_OWNER="${WHITE_LIST_OWNER}")

		target_link_libraries(${PREFIX} -lsecgear_tee)

		add_custom_command(TARGET ${PREFIX}
			POST_BUILD
			COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt
			-o ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT})

		install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT}
			DESTINATION /data
			PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE  WORLD_READ  WORLD_EXECUTE)

	endif()

manifest.txt：itrustee安全侧配置文件，后面对该文件进行详解
指定itrustee特性编译选项，设置引用头文件和动态库的路径。
前面声明的白名单在这里定义。
itrustee需要链接secgear_tee动态库，提供seal接口等。

	if(CC_SGX)
		set(SGX_DIR ${SGXSDK})
		set(CMAKE_C_FLAGS "${COMMON_C_FLAGS} -m64 -fvisibility=hidden")
		set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS}  -s")
		set(LINK_LIBRARY_PATH ${SGX_DIR}/lib64)

		if(CC_SIM)
			set(Trts_Library_Name sgx_trts_sim)
			set(Service_Library_Name sgx_tservice_sim)
		else()
			set(Trts_Library_Name sgx_trts)
			set(Service_Library_Name sgx_tservice)
		endif()

		set(Crypto_Library_Name sgx_tcrypto)

		set(CMAKE_SHARED_LINKER_FLAGS  "${COMMON_C_LINK_FLAGS} -Wl,-z,defs -Wl,-pie -Bstatic -Bsymbolic -eenclave_entry \
			-Wl,--export-dynamic -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/Enclave.lds")

		if(${CMAKE_VERSION} VERSION_LESS "3.13.0")
			link_directories(${LINK_LIBRARY_PATH})
		endif()

		add_library(${PREFIX}  SHARED ${SOURCE_FILES} ${AUTO_FILES})

		target_include_directories(${PREFIX} PRIVATE
				${CMAKE_CURRENT_BINARY_DIR}
				${SGX_DIR}/include/tlibc
				${SGX_DIR}/include/libcxx
				${SGX_DIR}/include
				${LOCAL_ROOT_PATH}/inc/host_inc
				${LOCAL_ROOT_PATH}/inc/host_inc/sgx)

		if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13.0")
			target_link_directories(${PREFIX} PRIVATE
					${LINK_LIBRARY_PATH})
		endif()

		target_link_libraries(${PREFIX}  -Wl,--whole-archive ${Trts_Library_Name} -Wl,--no-whole-archive
					-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l${Crypto_Library_Name} -l${Service_Library_Name}   -Wl,--end-group)
		add_custom_command(TARGET ${PREFIX}
		POST_BUILD
		COMMAND openssl genrsa -3 -out ${PEM} 3072
		COMMAND bash ${SIGN_TOOL} -d sign -x sgx -i lib${PREFIX}.so -k ${PEM} -o ${OUTPUT} -c ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml)
	endif()


在SGX硬件环境上，指定一些与sgx相关的编译选项、链接选项。链接动态库时有所不同，因为itrustee是一个具有更多功能的安全操作系统。提供如muslibc和openssl。在编译和链接itrustee时不用链接一些基本库，但是sgx没有OS概念。所以要在安全侧调用这些基本库的接口都要以静态的形式在sgxsdk中给出。例如"sgx_trts"

有关更多详细信息，请参阅sgx示例的Makefile。最后用enclave配置文件完成签名，稍后将进行介绍。secGear尚不支持远程身份验证。

#### 4.3 编写安全侧配置文件

编写与sgx enclave相关的配置文件中Enclave.config.xml文件及enclave.lds文件与官方sgx配置相同。详情参阅官方开发文档。

编写itrustee enclave相关配置文件
mainfest.txt.in:其中gpd.ta.appID 为动态生成uuid。其他配置参见itrustee开发文档。


#### 5 构建 安装

进入开发目录：cd .../secGear/example/test/
创建debug目录：mkdir debug && cd debug
cmake构建：cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=ON -DSGXSDK=sgx_sdk path .. &&  make && sudo make install （sgx硬件环境）
          cmake -DCMAKE_BUILD_TYPE=Debug -DCC_GP=ON -DiTrusteeSDK=gp_sdk path .. && make && sudo make install （itrustee硬件环境）

Log
---
非安全侧日志记录：

非安全侧是开发与普通开发环境一样，可使用通用打印日志接口。

安全侧日志记录：

由于各架构安全能力不同的限制，为了像非安全侧一样开发使用日志打印功能，因为我们提供了PrintInfo接口将安全端日志记录到syslog系统中。
相关配置文件为 conf/logrotate.d/secgear和conf/rsyslog.d/secgear.conf文件，安装时将安装在系统目录/etc/中。

注意：在itrustee上，需要include secgear_log.h头文件，但是sgx不需要，sgx通过ocall功能实现的，所以相关代码生成在辅助代码中。
当文件安装成功后需要运行"systemctl restart rsyslog"使日志功能生效。

日志等级：

    PRINT_ERROR    0
    PRINT_WARNING  1
    PRINT_STRACE   2
    PRINT_DEBUG    3

使用ocall
---------

目前ocall仅在sgx平台支持，itrustee尚不支持。

seal, generate_random接口
--------------------------------------

接口定义在secgear_dataseal.h、secgear_random.h中。
注意：由于itrustee派生密钥的功能仍然不完善，因此目前还没有与密封相关的接口在itrustee平台上支持。

远程证明（尚不支持）
--------------------------------------

了解更多关于codegener
--------------------------------------

secGear引入EDL(Enclave Description Language)和中间代码辅助生成工具codegener。edl与intel sgx定义兼容。


- [了解更多关于codegener](./docs/codegener.md)

了解更多关于sign_tool
-----------------------------


- [了解更多关于签名工具](./docs/sign_tool.md)

里程碑
---------
<img src="docs/milestone.png" alt="secGear" style="zoom:80%;" />
