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
	if(CC_GP)
		set(CODETYPE trustzone)
		set(CODEGEN codegen_arm64)
		execute_process(COMMAND uuidgen -r OUTPUT_VARIABLE UUID)
		string(REPLACE "\n" "" UUID ${UUID})
		add_definitions(-DPATH="/data/${UUID}.sec")
	endif()
	if(CC_SGX)
		set(CODETYPE sgx)
		set(CODEGEN codegen_x86_64)
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

