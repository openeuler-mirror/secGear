<img src="../../docs/logo.png" alt="secGear" style="zoom:100%;" />

switchless
============================

介绍
-----------

 **技术定义：** switchless是一种通过共享内存减少REE与TEE上下文切换及数据拷贝次数，优化REE与TEE交互性能的技术。

 **典型应用场景：** 传统应用做机密计算改造拆分成非安全侧CA与安全侧TA后

- 当CA业务逻辑中存在频繁调用TA接口时，调用中间过程耗时占比较大，严重影响业务性能。
- 当CA与TA存在频繁大块数据交换时，普通ECALL调用底层会有多次内存拷贝，导致性能低下。
  针对以上两种典型场景，可以通过switchless优化交互性能，降低机密计算拆分带来的性能损耗，最佳效果可达到与拆分前同等数量级。

 **支持硬件平台：** 

- Intel SGX
- ARM TrustZone 鲲鹏920

switchless开发流程
------------------------------

基于secGear API开发应用的具体流程请参考[HelloWorld开发流程](../../README.md)

以[switchless](../switchless)样例源码为例详细介绍switchless开发步骤。

### 1 编写edl接口文件

如下定义了ecall函数get_string_switchless。

[参考 switchless edl文件](./switchless.edl)

```
	enclave {
        include "secgear_urts.h"
        from "secgear_tstdc.edl" import *;
        from "secgear_tswitchless.edl" import *;
        trusted {
            public int get_string_switchless([out, size=32]char *buf) transition_using_threads;
        };
    };
```

switchless函数需添加'transition_using_threads'标识。

### 2 编写非安全侧代码
开发者在非安全侧需要完成如下步骤：
- 调用cc_enclave_create创建enclave
- 调用cc_malloc_shared_memory创建共享内存
- 调用ecall函数
- 调用cc_free_shared_memory释放共享内存
- 调用cc_enclave_destroy销毁enclave

[参考 switchless main.c文件](./host/main.c)
```
    // 创建enclave
    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &features, 1, context);
    ...

    // 创建共享内存
    char *shared_buf = (char *)cc_malloc_shared_memory(context, BUF_LEN);
    ...

    // 调用ecall函数，对应安全侧函数在enclave/enclave.c中
    res = get_string_switchless(context, &retval, shared_buf);
    ...

    // 释放共享内存
    res = cc_free_shared_memory(context, shared_buf);
    ...

    // 销毁enclave
    res = cc_enclave_destroy(context);
```
[异步switchless调用](../switchless_performance/host/main.c)，在调用ecall函数处变化有如下2点：
- 发起异步调用
```
    // 调用异步ecall函数，对应安全侧函数在enclave/enclave.c中
    res = get_string_switchless_async(context, &task_id, &retval, shared_buf);
    ...
```
- 查询异步调用结果
```
    // 根据第一步返回的task_id, 查询异步调用结果
    ret = cc_sl_get_async_result(context, task_id, &retval);
    ...
```
调用cc_enclave_create时，需传入switcheless特性对应参数“ENCLAVE_FEATURE_SWITCHLESS”，才能正常使用使用switchless特性。
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
                               --search-path ${SGXSDK}/include)
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
| cc_malloc_shared_memory()  | 创建安全环境与非安全环境可同时访问的共享内存。<br>参数：<br>enclave，安全环境上下文句柄。因不同平台共享内存模型不同，同时保持接口跨平台的一致性，该参数仅在ARM平台被使用，SGX平台该入参会被忽略。<br>size，共享内存大小。<br>返回值：<br>NULL：共享内存申请失败。<br>其他：共享内存首地址<br> |
| cc_free_shared_memory()  | 释放共享内存。<br>参数：<br>enclave，安全环境上下文句柄。因不同平台共享内存模型不同，同时保持接口跨平台的一致性，该参数仅在ARM平台被使用（该参数必须与调用cc_malloc_shared_memory接口时传入的enclave保持一致），SGX平台该入参会被忽略。<br>ptr：cc_malloc_shared_memory接口返回的共享内存地址。<br>返回值：<br>CC_ERROR_BAD_PARAMETERS，入参非法。 <br>CC_ERROR_INVALID_HANDLE， 无效enclave或者传入的enclave与ptr所对应的enclave不匹配（仅在ARM平台生效，SGX平台会忽略enclave，故不会对enclave进行检查）。 <br>CC_ERROR_NOT_IMPLEMENTED，该接口未实现。 <br>CC_ERROR_SHARED_MEMORY_START_ADDR_INVALID， <br>ptr不是cc_malloc_shared_memory接口返回的共享内存地址（仅在ARM平台生效）。 <br>CC_ERROR_OUT_OF_MEMORY，内存不足（仅在ARM平台生效）。 <br>CC_FAIL，一般性错误。 <br>CC_SUCCESS，成功。|
| cc_sl_get_async_result()  | 检查异步调用结果并释放异步调用资源（当前仅支持ARM）。<br>参数：<br>enclave: 安全环境上下文句柄。<br>task_id: 异步调用任务编号。<br>retval: 用于接收返回值的缓冲区。<br>返回值：<br>CC_SUCCESS，异步调用成功。 <br>CC_ERROR_TASK_UNFINISH， 异步调用处理中。 <br>CC_ERROR_TASK_FAILED，异步调用框架执行失败。 <br>其他，一般性错误。|
