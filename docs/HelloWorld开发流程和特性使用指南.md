HelloWorld开发流程
------------------------------

基于secGear API开发应用主要分为五个部分：
- EDL(Enclave Definition Language)接口文件
- 非安全侧的代码
- 调用codegen工具，根据EDL文件生成非安全侧与安全侧交互代码
- 安全侧的代码的编写
- 调用sign_tool.sh对安全侧编译出的so做签名

以[HelloWorld](../examples/helloworld)样例源码为例详细介绍开发步骤。

### 1 编写edl接口文件
edl文件定义了非安全侧与安全侧交互的接口声明，类似于传统的头文件接口声明，由codegen辅助代码生成工具根据edl文件编译生成非安全侧与安全侧交互代码，从而帮助用户降低开发成本，聚焦业务逻辑。目前ocall仅在sgx平台支持，itrustee尚不支持。

如下定义了ecall函数get_string。

[参考 HelloWorld edl文件](../examples/helloworld/helloworld.edl)

```
	enclave {
		include "secgear_urts.h"
		from "secgear_tstdc.edl" import *;
		trusted {
			public int get_string([out, size=32]char *buf);
		};
	};
```

'include "secgear_urts.h" from "secgear_tstdc.edl" import *'是为了屏蔽SGX和iTrustee在调用libc库之间的差异，为了开发代码的一致性，默认导入这两个文件。

有关edl语法的详细信息，请参阅SGX开发文档定义的EDL(Enclave Definition Language)语法部分。

目前SGX和iTrustee在基本类型、指针类型和深拷贝方面是相互兼容的。对于user_check、private ecalls、switchless特性仅支持sgx硬件。

### 2 编写非安全侧代码
开发者在非安全侧需要完成如下步骤：
- 调用cc_enclave_create创建enclave
- 调用ecall函数
- 调用cc_enclave_destroy销毁enclave

[参考 HelloWorld main.c文件](../examples/helloworld/host/main.c)
```
    // 创建enclave
    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, context);
    ...

    // 调用ecall函数，对应安全侧函数在enclave/hello.c中
    res = get_string(context, &retval, buf);
    ...

    // 销毁enclave
    res = cc_enclave_destroy(context);
```

### 3 调用codegen工具
[参考 HelloWorld host/CMakeLists.txt文件](../examples/helloworld/host/CMakeLists.txt)

Helloworld样例的编译工程已经集成codegen的调用，如下。

```	
	if(CC_SGX)
		set(AUTO_FILES  ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.h ${CMAKE_CURRENT_BINARY_DIR}/${PREFIX}_u.c)
		add_custom_command(OUTPUT ${AUTO_FILES}
		DEPENDS ${CURRENT_ROOT_PATH}/${EDL_FILE}
		COMMAND ${CODEGEN} --${CODETYPE} --untrusted ${CURRENT_ROOT_PATH}/${EDL_FILE} --search-path ${LOCAL_ROOT_PATH}/inc/host_inc/sgx  --search-path ${SDK_PATH}/include)
	endif()
```


### 4 编写安全侧代码
开发者在安全侧需要完成：
- edl文件中定义的ecall函数的实现，edl文件相当于头文件

[参考 HelloWorld hello.c文件](../examples/helloworld/enclave/hello.c)

test_t.h：该头文件为自动生成代码工具codegen通过edl文件生成的头文件，该头文件命名为edl文件名加"_t"。

### 5 调用签名工具

[参考 HelloWorld enclave/CMakeLists.txt文件](../examples/helloworld/enclave/CMakeLists.txt)

使用SIGN_TOOL对编译出的.so文件进行签名。

### 6 配置开发者证书
仅适用鲲鹏平台，以[examples/helloworld](../examples/helloworld)样例介绍
- 修改uuid
  修改[examples/helloworld/CMakeLists.txt](../examples/helloworld/CMakeLists.txt)中uuid
  
```
if(CC_GP)
    set(CODETYPE trustzone)
    set(UUID f68fd704-6eb1-4d14-b218-722850eb3ef0)  # f68fd704-6eb1-4d14-b218-722850eb3ef0修改为自己申请证书对应的configs.xml中的uuid
    add_definitions(-DPATH="/data/${UUID}.sec")
  endif()
```

- 配置证书路径
修改[examples/helloworld/enclave/config_cloud.ini](../examples/helloworld/enclave/config_cloud.ini)配置证书路径

```
;private key for signing TA
;[private key owned by yourself]
secSignKey = /home/TA_cert/private_key.pem    # 证书对应的私钥路径
;;;
;config file
;[signed config file by Huawei]
configPath = /home/TA_cert/secgear-app1/config  # config开发者证书的路径
```

- 修改manifest.txt
参照申请证书是的configs.xml字段，修改[manifest.txt](../examples/helloworld/enclave/manifest.txt)中字段
如果configs.xml中存在，manifest.txt中没有，需要自行添加。

```
gpd.ta.appID:   		f68fd704-6eb1-4d14-b218-722850eb3ef0
gpd.ta.service_name:		rsa-demo
gpd.ta.singleInstance:		true
gpd.ta.multiSession: 		false
gpd.ta.instanceKeepAlive:	false
gpd.ta.dataSize:		819200
gpd.ta.stackSize:		40960
```

- 开启签名
在[examples/helloworld/enclave/CMakeLists.txt](../examples/helloworld/enclave/CMakeLists.txt)中找到如下注释的行，打开注释

```
        add_custom_command(TARGET ${PREFIX}
    	      POST_BUILD
	      COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt -m ${CMAKE_CURRENT_SOURCE_DIR}/config_cloud.ini -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT})

          install(FILES ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT}  
              DESTINATION /data
              PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE  WORLD_READ  WORLD_EXECUTE)
```

配置开发者证书完成，重新编译安装执行即可。

switchless特性
-------------------------

### 1 switchless特性介绍
**技术定义：** switchless是一种通过共享内存减少REE与TEE上下文切换及数据拷贝次数，优化REE与TEE交互性能的技术。

 **典型应用场景：** 传统应用做机密计算改造拆分成非安全侧CA与安全侧TA后

- 当CA业务逻辑中存在频繁调用TA接口时，调用中间过程耗时占比较大，严重影响业务性能。
- 当CA与TA存在频繁大块数据交换时，普通ECALL调用底层会有多次内存拷贝，导致性能低下。
  针对以上两种典型场景，可以通过switchless优化交互性能，降低机密计算拆分带来的性能损耗，最佳效果可达到与拆分前同等数量级。

 **支持硬件平台：** 

- Intel SGX
- ARM TrustZone 鲲鹏920

### 2 约束限制
虽然开启switchless节省了一定时间，但它们需要额外的线程来为调用提供服务。如果工作线程忙于等待消息，将会消耗大量CPU，另外更多的工作线程通常意味着更多的CPU资源竞争和更多的线程上下文切换，反而可能损害性能，所以switchless的最佳配置是经过实际业务模型与性能测试，在资源占用与性能要求中选出平衡点。

### 3 特性配置项规格
用户调用cc_enclave_create创建Enclave时，需在feature参数中传入switchless的特性配置，配置项如下：
```
typedef struct {
	uint32_t num_uworkers;
	uint32_t num_tworkers;
	uint32_t switchless_calls_pool_size;
	uint32_t retries_before_fallback;
	uint32_t retries_before_sleep;
	uint32_t parameter_num;
	uint32_t workers_policy;
	uint32_t rollback_to_common;
	cpu_set_t num_cores;
} cc_sl_config_t;
```
各配置项规格如下表：

| 配置项 |   说明   |
| ------------ | ---- |
|       num_uworkers       |   非安全侧代理工作线程数，用于执行switchless OCALL，当前该字段仅在SGX平台生效，ARM平台可以配置，但是因ARM平台暂不支持OCALL，所以配置后不会生效。<br>规格： <br>ARM：最大值：512；最小值：1；默认值：8（配置为0时） <br>SGX：最大值：4294967295；最小值：1|
|      num_tworkers        |   安全侧代理工作线程数，用于执行switchless ECALL。<br>规格： <br>ARM：最大值：512；最小值：1；默认值：8（配置为0时） <br>SGX：最大值：4294967295；最小值：1|
|     switchless_calls_pool_size         |    switchless调用任务池的大小，实际可容纳switchless_calls_pool_size * 64个switchless调用任务（例：switchless_calls_pool_size=1，可容纳64个switchless调用任务）。<br>规格：<br>ARM：最大值：8；最小值：1；默认值：1（配置为0时）<br>SGX：最大值：8；最小值：1；默认值：1（配置为0时）|
|        retries_before_fallback      |    执行retries_before_fallback次汇编pause指令后，若switchless调用仍没有被另一侧的代理工作线程执行，就回退到switch调用模式，该字段仅在SGX平台生效。<br>规格：br>SGX：最大值：4294967295；最小值：1；默认值：20000（配置为0时）|
|      retries_before_sleep        |   执行retries_before_sleep次汇编pause指令后，若代理工作线程一直没有等到有任务来，则进入休眠状态，该字段仅在SGX平台生效。<br>规格：<br>SGX：最大值：4294967295；最小值：1；默认值：20000（配置为0时）|
|       parameter_num       |   switchless函数支持的最大参数个数，该字段仅在ARM平台生效。<br>规格：<br>ARM：最大值：16；最小值：0|
|       workers_policy       |   switchless代理线程运行模式，该字段仅在ARM平台生效。<br>规格：<br>ARM：<br>WORKERS_POLICY_BUSY：代理线程一直占用CPU资源，无论是否有任务需要处理，适用于对性能要求极高且系统软硬件资源丰富的场景；<br>WORKERS_POLICY_WAKEUP：代理线程仅在有任务时被唤醒，处理完任务后进入休眠，等待再次被新任务唤醒|
|       rollback_to_common       |   异步switchless调用失败时是否回退到普通调用，该字段仅在ARM平台生效。<br>规格：<br>ARM：0：否，失败时仅返回相应错误码；其他：是，失败时回退到普通调用|
|       num_cores            | 用于设置安全侧线程绑核 <br>规格：<br>最大值为当前环境CPU核数 |

### 4 switchless开发流程
[参考 switchless README.md文件](../examples/switchless/README.md)

### 5 switchless性能优化
#### 5.1 CPU绑核
switchless机制支持配置TA线程绑核，降低频繁调度切换开销，来优化REE和TEE业务线程性能。

使用方式：cpu_set_t数组配置字段，支持TA线程配置绑核参数，将配置通过共享内存传入TA侧，并在switchless初始化TA线程池时，按照配置参数设置绑核。

#### 5.2 通过openSession注册共享内存
secGear新增支持通过openSession注册共享内存，并对新老版本注册共享内存做兼容。默认使用openSession方式，当TEEOS不支持时，回退使用ecall方式注册共享内存。

注：申请共享内存成功时，如果出现如下打印，表示先尝试使用openSession注册共享内存失败，再尝试ecall注册方式成功，可忽略错误打印
```
  ERROR:[handle_open_session_register_shared_memory] Handle ecall with new session, failed to open session, ret:ffff0000, origin:3
```
### 6 常见问题
- sgx环境下开启switchless特性创建enclave后，直接销毁enclave会产生core dump

    sgx开启switchless需有一下两步：
    
    1. cc_enclave_create时传入switchless feature参数
    2. 在第一次ecall调用中初始化switchless线程调度
    
    如果没有调用ecall函数，就直接调用cc_enclave_destroy，会在sgx库中销毁switchless调度线程时异常。
    
    由于switchless的实际应用场景是存在频繁ecall调用，所以初始化switchless特性后，通常会有ecall调用，不会存在问题。
    

远程证明特性
-------------------------

### 1 远程证明特性介绍
**技术定义：** 目前不同的TEE的远程证明报告格式及验证流程各有差异，用户对接不同的TEE，需要集成不同TEE证明报告的验证流程，增加了用户的集成负担，并且不利于扩展新的TEE类型。远程证明服务将TEE证明报告的验证独立出来，同时支持不同TEE报告的验证，易扩展，用户仅需集成证明代理即可实现不同TEE之间的相互验证，并建立安全通道，大大降低了机密计算的使用门槛，促进机密计算生态的发展

 **支持硬件平台：** 

- virtCCA(920B/C)
- ARM TrustZone 鲲鹏920

### 2 约束限制
当前仅提供远程证明服务相关组件，服务由用户自己部署、运维。

### 3 远程证明API清单
|  接口   | 接口说明  |
|  ----  | ----  |
| get_report()  | 获取证明报告。<br>参数：<br>&uuid：唯一标识。<br>&challenge: 随机数nonce。<br>返回值：<br>成功，返回证明报告，否则返回失败。<br> |
| verify_report()  | 校验证明报告。<br>参数：<br>&challenge: 获取证明报告时用户输入的nonce随机数。<br>&report：待校验的证明报告。<br>返回值：<br>校验成功返回0，否则返回失败。<br> |

### 4 远程证明开发流程 
- 编译流程

  当前使用cargo build对service/attestation/attestation-agent路径进行编译，提供如下编译选项：
```
    --features
        all-attester ： 编译所有平台的获取报告agent
        itrustee-attester ： 编译itrustee的获取报告agent
        virtcca-attester ：编译virtcca的获取报告agent

        all-verifier : 编译所有平台的报告验证service
        itrustee-verifier : 编译itrustee的报告验证service
        virtcca-verifier: 编译virtcca的报告验证service

        no_as : 不对接as服务
```

  例：使用如下命令编译itrustee平台的报告获取和验证：
```
     cargo build --features no_as,all-attester,itrustee-verifier --lib
```
- 本地验证使用方法

  注意：

      itrustee平台需先自行使用源码编译libqca和qta，且用户二进制要同时链接libqca和libattestation_agent.so文件；
      virtcca平台需要下载virtCCA_sdk和virtCCA_sdk-devel软件包。

  1. 编译证明代理期间，配置no_as，把校验插件框架编译到证明代理中，本地调用证明报告校验插件框架完成验证。本地验证时需要用户配置TEE公钥证书、TCB和应用基线值。

  2. 使用如下demo：
```
    #include <stdlib.h>
    #include <stdio.h>
    #include <string.h>
    #include "rust_attestation_agent.h"

    int main() {
            char *ptr = "f68fd704-6eb1-4d14-b218-722850eb3ef0";
            Vec_uint8_t uuid = {
                    .ptr = (uint8_t *)ptr,
                    .len = strlen(ptr),
                    .cap = strlen(ptr),
            };

            uint8_t nonce[16] = {1};
            Vec_uint8_t challenge = {
                    .ptr = (uint8_t *)&nonce,
                    .len = 16,
                    .cap = 16,
            };

            // 获取报告
            Vec_uint8_t report = get_report(&uuid, &challenge);
            int ret = -1;
            if (report.cap != 0) {
                // 验证报告
                ret = verify_report(&challenge, &report);
            }

            printf("ret:%d\n", ret);
            free_report(report);
            return 0;
    }
```


中间层组件使用指导
-------------------------

secGear中间层提供了一些常用的安全组件，帮助用户快速构建安全应用。用户也可以基于secGear接口开发自己的组件，开发指导参考Helloworld样例，本节主要介绍基于secGear改造后的安全组件使用方法，以一个简单共享库为例说明。

### 1 原始库

该库提供了compare_num函数，功能是比较两个数A和B的大小。该库的程序包含data_process.h和data_process.c文件，目录结构如下：

```
. （编译生成data_process.so二进制）
├── data_process.c
└── data_process.h
```

data_process.h为对外提供的接口文件，data_process.c为源码文件，两个文件的具体内容如下：

data_process.h文件：

```c
int compare_num(const int A);
```

data_process.c文件：

```c
static int B = 20;

int compare_num(const int A) {
    return A >= B;
}
```

在编译完成后源码文件会生成一个data_process.so动态库（或者静态库），data_process.h为用户提供函数声明。

### 2 基于secGear改造的secgear_data_process.so

当数据B为用户隐私数据时，不希望计算平台或其他用户获取到该隐私数据，可以利用secGear将数据B及数据B的处理程序(compare_num函数)分离出来，放入enclave中执行，保护用户隐私不泄露。以下demo为了简化过程，数据B被硬编码在处理程序中（一般情况下B被加密后传入enclave中，在enclave中解密后与A比较，返回比较结果）。

改造后代码由四部分组成：edl文件、安全侧程序（enclave）、非安全侧程序（host）和对外提供的头文件，改造后的目录结构为：

```
.
├── data_process.edl
├── data_process.h
├── enclave （编译生成enclave.signed.so二进制）
│   └── sec_data_process.c  // 实现ecall_compare_num
└── host （编译生成data_process.so二进制）
    └── data_process.c  // compare_num函数调用ecall_compare_num
```

在编译后得到secgear_data_process.so文件，对外接口依然是compare_num。

### 3 用户APP
用户APP在调用原始库与安全改造后的库函数时无变化，仅链接so时，链接secgear_data_process.so即可。
用户APP使用改造后的组件库，无需再做机密计算安全改造，即可享受机密计算带来的安全，大大降低了用户开发成本。


API清单
------------------------------

### 函数接口
- host侧接口

|  接口   | 接口说明  |
|  ----  | ----  |
| cc_enclave_create()  | 用于创建安全侧的安全进程，针对安全区进程进行内存和相关上下文的初始化 |
| cc_enclave_destroy()  | 用于销毁相关安全进程，对安全内存进行释放 |
| cc_malloc_shared_memory()  | 用于开启switchless特性后，创建共享内存 |
| cc_free_shared_memory()  | 用于开启switchless特性后，释放共享内存 |
| cc_sl_get_async_result()  | 检查异步调用结果并释放异步调用资源（当前仅支持ARM） |

- enclave侧接口

|  接口   | 接口说明  |
|  ----  | ----  |
| cc_enclave_get_sealed_data_size()  | 用于获取加密后 sealed_data 数据占用的总大小，主要用于解密后需要分配的内存空间 |
| cc_enclave_get_encrypted_text_size()  | 获取加密数据中加密消息的长度 |
| cc_enclave_unseal_data()  | 用于解密 enclave 密封过的数据，用于将外部持久化数据重新导回 enclave 环境中 |
| cc_enclave_get_add_text_size()  | 获取加密数数据中附加消息的长度 |
| cc_enclave_seal_data()  | 用于加密 enclave 内部数据，使数据可以在 enclave 外部持久化存储 |
| cc_enclave_memory_in_enclave()  | 用于校验指定长度的内存地址是否都属于安全侧内存 |
| cc_enclave_memory_out_enclave()  | 用于校验指定长度的内存地址是否都属于非安全侧内存 |
| cc_enclave_generate_random()  | 用于在安全侧生成密码安全的随机数 |
| PrintInfo()  | 用于调试的日志分级打印功能 |

### 文件接口
- edl文件：用户需要通过edl文件定义非安全侧与安全侧交互接口原型。

### 工具接口
|  接口   | 接口说明  |
|  ----  | ----  |
| sign_tool.sh  | sign_tool 包含 sign 指令（对 enclave 进行签名）和 digest 指令（生成摘要值） |
| codegen  | 代码生成工具，根据edl文件编译生成非安全侧与安全侧交互代码 |

[sign_tool.sh](../docs/sign_tool.md) 和[codegen](../docs/codegener.md)可使用-h打印帮助信息。