<img src="docs/logo.png" alt="secGear" style="zoom:100%;" />

switchless
============================

介绍
-----------

Switchless方案是通过共享内存减少安全侧与非安全侧交互中数据拷贝次数来实现，将调用的数据写入共享内存，安全侧去访问并监控共享内存，发现有变化了，线程就去处理，这样减少上下文切换和数据拷贝的开销，大幅提升性能。

switchless开发流程
------------------------------

基于secGear API开发应用的具体流程请参考[HelloWorld开发流程](../../README.md)

以[switchless](../switchless)样例源码为例详细介绍switchless开发步骤。

### 1 编写edl接口文件

如下定义了ecall函数test_toupper。

[参考 switchless edl文件](./switchless.edl)

```
	enclave {
		include "secgear_urts.h"
		from "secgear_tstdc.edl" import *;
		trusted {
			public void test_toupper([in, out, size=len]char *buf, int len) transition_using_threads;
		};
	};
```

switchless函数需添加'transition_using_threads'标识。

### 2 编写非安全侧代码
开发者在非安全侧需要完成如下步骤：
- 调用cc_enclave_create创建enclave
- 调用cc_malloc_shared_memory创建共享内存
- 调用cc_register_shared_memory注册共享内存
- 调用ecall函数
- 调用cc_unregister_shared_memory去注册共享内存
- 调用cc_free_shared_memory释放共享内存
- 调用cc_enclave_destroy销毁enclave

[参考 switchless main.c文件](./host/main.c)
```
    // 创建enclave
    ret = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, features, 1, &g_enclave);
    ...

	// 创建共享内存
    char *buf = (char *)cc_malloc_shared_memory(&g_enclave, len);
    ...

	// 注册共享内存
    ret = cc_register_shared_memory(&g_enclave, buf);
    ...

    // 调用ecall函数，对应安全侧函数在enclave/enclave.c中
    test_toupper(&g_enclave, buf, strlen(TEST_STR));
    ...

	// 去注册共享内存
    ret = cc_unregister_shared_memory(&g_enclave, buf);
    ...

	// 释放共享内存
    ret = cc_free_shared_memory(&g_enclave, buf);
    ...

    // 销毁enclave
    res = cc_enclave_destroy(context);
```

### 3 调用codegen工具
[参考 switchless host/CMakeLists.txt文件](./host/CMakeLists.txt)

switchless样例的编译工程已经集成codegen的调用，如下。

```	
	if(CC_SGX)
		set(AUTO_FILES ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c)
		add_custom_command(OUTPUT ${AUTO_FILES}
			DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
			COMMAND ${CODEGEN} --${CODETYPE}
							--untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE}
							--search-path /usr/include/secGear
							--search-path ${SDK_PATH}/include)
	endif()
```


### 4 编写安全侧代码
开发者在安全侧需要完成：
- edl文件中定义的ecall函数的实现，edl文件相当于头文件

[参考 switchless enclave.c文件](./enclave/enclave.c)

test_t.h：该头文件为自动生成代码工具codegen通过edl文件生成的头文件，该头文件命名为edl文件名加"_t"。

### 5 调用签名工具

[参考 switchless enclave/CMakeLists.txt文件](./enclave/CMakeLists.txt)

使用SIGN_TOOL对编译出的.so文件进行签名。

switchless API清单
------------------------------
### 函数接口
- host侧接口

|  接口   | 接口说明  |
|  ----  | ----  |
| cc_malloc_shared_memory()  | 创建共享内存 |
| cc_free_shared_memory()  | 释放共享内存 |
| cc_register_shared_memory()  | 注册共享内存 |
| cc_unregister_shared_memory() | 去注册共享内存 |
