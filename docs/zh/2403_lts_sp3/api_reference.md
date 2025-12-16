# 接口说明

secGear 机密计算统一编程框架分为安全侧和非安全侧，这里给出用户开发应用程序所需的接口。除这些接口外，安全侧还继承了 ARM TrustZone 和 Intel SGX 的开源 POSIC 接口。

## cc_enclave_create

创建 enclave 接口

**功能**：

初始化接口，函数根据不同 type，调用不同的 TEE 创建函数，完成不同 TEE 方案关于 enclave 上下文初始化，由非安全侧调用

> [!NOTE]说明
> 由于 Intel SGX 限制，多线程并发调用 cc_enclave_create 时存在内存映射的竞争关系，会导致创建 enclave 概率性失败。所以编码时要避免线程并发调用 cc_enclave_create。

**函数声明：**

cc_enclave_result_t cc_enclave_create(const char*path, enclave_type_t type, uint32_t version,uint32_t flags,const enclave_features_t* features,uint32_t features_count,
 cc_enclave_t  ** enclave);

**参数：**

- Path：入参，要加载的 enclave 路径
- Type：入参，用来指定 TEE 解决方案， 如 SGX_ENCLAVE_TYPE、GP_ENCLAVE_TYPE、AUTO_ENCLAVE_TYPE
- version：入参，指定的 enclave engine 的版本，目前只有一个版本，取值为 0
- Flags：入参，标志位，说明这个 enclave 运行状态，例如调试状态 SECGEAR_DEBUG_FLAG、模拟状态 SECGEAR_SIMULATE_FLAG（目前不支持）
- features：入参，用于设置一些关于 enclave 支持的特性，例如 SGX 的 PCL、 switchless 等。目前不支持，请设置为 NULL
- features_count：入参，入参 features 特性结构体的数量。目前不支持，请设置为 0
- enclave：出参，创建的 enclave 上下文

**返回值：**

- CE_SUCCESS：认证信息验证成功
- CE_ERROR_INVALID_PARAMETER：输入参数有误
- CE_ERROR_OUT_OF_MEMORY：无可用内存
- CC_FAIL：通用错误
- CC_ERROR_UNEXPECTED：不可预期错误
- CC_ERROR_ENCLAVE_MAXIMUM：单个 app 创建的 enclave 数量达到最
- CC_ERROR_INVALID_PATH：安全二进制路径无效
- CC_ERROR_NO_FIND_REGFUNC：enclave 引擎搜索失败

## cc_enclave_destroy

销毁 enclave 接口

**功能**：

调用不同 TEE 的退出函数，释放已经创建的 enclave 实体，由非安全侧调用

**函数声明：**

cc_enclave_result_t cc_enclave_destroy (cc_enclave_t ** enclave)；

**参数：**

- enclave：入参，已经创建 enclave 的上下文

**返回值：**

- CE_SUCCESS：认证信息验证成功
- CE_ERROR_INVALID_PARAMETER：输入参数有误
- CE_ERROR_OUT_OF_MEMORY：无可用内存
- CC_ERROR_NO_FIND_UNREGFUNC：enclave引擎搜索失败
- CC_FAIL：通用错误
- CC_ERROR_UNEXPECTED：不可预期错误

## cc_malloc_shared_memory

创建共享内存

**功能**：

开启switchless特性后，创建安全环境与非安全环境可同时访问的共享内存，由非安全侧调用

**函数声明：**

void *cc_malloc_shared_memory(cc_enclave_t*enclave, size_t size);

**参数：**

- enclave：入参，安全环境上下文句柄。因不同平台共享内存模型不同，同时为了保持接口跨平台一致性，该参数仅在ARM平台被使用，SGX平台该入参会被忽略
- size：入参，共享内存大小

**返回值：**

- NULL：共享内存申请失败
- 其他：为创建的共享内存的首地址

## cc_free_shared_memory

释放共享内存

**功能**：

开启switchless特性后，释放共享内存，由非安全侧调用

**函数声明：**

cc_enclave_result_t cc_free_shared_memory(cc_enclave_t *enclave, void*ptr);

**参数：**

- enclave：入参，安全环境上下文句柄。因不同平台共享内存模型不同，同时为了保持接口跨平台一致性，该参数仅在ARM平台被使用（该参数必须与调用cc_malloc_shared_memory接口时传入的enclave保持一致），SGX平台该入参会被忽略
- ptr：入参，cc_malloc_shared_memory接口返回的共享内存地址

**返回值：**

- CC_ERROR_BAD_PARAMETERS：入参非法
- CC_ERROR_INVALID_HANDLE：无效enclave或者传入的enclave与ptr所对应的enclave不匹配（仅在ARM平台生效，SGX平台会忽略enclave，故不会对enclave进行检查）
- CC_ERROR_NOT_IMPLEMENTED：该接口未实现
- CC_ERROR_SHARED_MEMORY_START_ADDR_INVALID：ptr不是cc_malloc_shared_memory接口返回的共享内存地址（仅在ARM平台生效）
- CC_ERROR_OUT_OF_MEMORY：内存不足（仅在ARM平台生效）
- CC_FAIL：一般性错误
- CC_SUCCESS：成功

## cc_enclave_generate_random

随机数生成

**功能**：

用于在安全侧生成密码安全的随机数

**函数声明：**

cc_enclave_result_t cc_enclave_generate_random(void *buffer, size_t size);

**参数：**

- *buffer：入参，生成随机数的缓冲区
- size：入参，缓冲区的长度

**返回值：**

- CE_OK：认证信息验证成功
- CE_ERROR_INVALID_PARAMETER：输入参数有误
- CE_ERROR_OUT_OF_MEMORY：无可用内存

## cc_enclave_seal_data

数据持久化

**功能**：

用于加密 enclave 内部数据，使数据可以在 enclave 外部持久化存储，由安全侧调用

**函数声明：**

cc_enclave_result_t cc_enclave_seal_data(uint8_t *seal_data, uint32_t seal_data_len,

​    cc_enclave_sealed_data_t *sealed_data, uint32_t sealed_data_len,

​    uint8_t *additional_text, uint32_t additional_text_len);

**参数：**

- seal_data：入参，需要加密的数据
- seal_data_len：入参，需要加密数据的长度
- sealed_data：出参，加密后的数据处理句柄
- sealed_data_len：出参，加密后的密文长度
- additional_text：入参，加密所需的附加消息
- additional_text_len：入参，附加消息长度

**返回值：**

- CE_SUCCESS：数据加密成功
- CE_ERROR_INVALID_PARAMETER：输入参数有误
- CE_ERROR_OUT_OF_MEMORY：无可用内存
- CC_ERROR_SHORT_BUFFER：传入的buffer过小
- CC_ERROR_GENERIC：底层硬件通用错误

## cc_enclave_unseal_data

数据解密

**功能**：

用于解密 enclave 密封过的数据，用于将外部持久化数据重新导回 enclave 环境中，由安全侧调用

**函数声明：**

`cc_enclave_result_t cc_enclave_unseal_data(cc_enclave_sealed_data_t *sealed_data, uint8_t *decrypted_data, uint32_t *decrypted_data_len,uint8_t *additional_text, uint32_t *additional_text_len);`

**参数：**

- sealed_data：入参，已加密数据的句柄
- decrypted_data：出参，解密之后的密文数据buffer
- decrypted_data_len：出参，解密后密文长度
- additional_text：出参，解密后附加消息
- additional_text_len：出参，解密后附加消息长度

**返回值：**

- CE_SUCCESS：数据解密成功
- CE_ERROR_INVALID_PARAMETER：输入参数有误
- CE_ERROR_OUT_OF_MEMORY：无可用内存
- CC_ERROR_SHORT_BUFFER：传入的buffer过小
- CC_ERROR_GENERIC：底层硬件通用错误

## cc_enclave_get_sealed_data_size

获取加密数据的大小

**功能**：

用于 sealed_data 数据的大小，主要用于分配解密后的数据空间，由安全侧与非安全侧皆可调用

**函数声明：**

uint32_t cc_enclave_get_sealed_data_size(const uint32_t add_len, const uint32_t seal_data_len);

**参数：**

- add_len：入参，附加消息长度
- sealed_data_len：入参，加密信息的长度

**返回值：**

- UINT32_MAX：参数错误或函数执行错误
- others：函数执行成功，返回值为当前 sealed_data 结构的大小

## cc_enclave_get_encrypted_text_size

获取加密消息的长度

**功能**：

获取加密数数据中加密消息的长度，由安全侧调用

**函数声明：**

uint32_t cc_enclave_get_encrypted_text_size(const cc_enclave_sealed_data_t *sealed_data);

**参数：**

- sealed_data：入参，加密数据的句柄

**返回值：**

- UINT32_MAX：参数错误或函数执行错误
- others：函数执行成功，返回值为当前 sealed_data 中加密消息的长度

## cc_enclave_get_add_text_size

获取附加消息的长度

**功能**：

获取加密数数据中附加消息的长度，由安全侧调用

**函数声明：**

uint32_t cc_enclave_get_add_text_size(const cc_enclave_sealed_data_t *sealed_data);

**参数：**

- sealed_data：入参，加密数据的句柄

**返回值：**

- UINT32_MAX：参数错误或函数执行错误
- others：函数执行成功，返回值为当前sealed_data中附加消息的长度

## cc_enclave_memory_in_enclave

安全内存检查

**功能**：

用于校验指定长度的内存地址是否都属于安全侧内存，由安全侧调用

**函数声明：**

bool cc_enclave_memory_in_enclave(const void *addr, size_t size);

**参数：**

- *addr：入参，指定需要校验的内存地址
- size：入参，自内存地址起需要校验的长度

**返回值：**

- true：指定区域内存都在安全区范围内
- false：指定区域的内存有部分或者全部不在安全范围内

## cc_enclave_memory_out_enclave

安全内存检查

**功能**：

用于校验指定长度的内存地址是否都属于非安全侧内存，由安全侧调用

**函数声明：**

bool cc_enclave_memory_out_enclave(const void *addr, size_t size);

**参数：**

- *addr：入参，指定需要校验的内存地址
- size：入参，自内存地址起需要校验的长度

**返回值：**

- true：指定区域内存都在非安全区
- false：指定区域的内存有部分或者全部在安全区

## PrintInfo

消息打印

**功能**：

用于安全侧日志的打印，本接口输出安全侧用户想打印的信息，输入日志保存在非安全侧/var/log/secgear/secgear.log中

**函数声明：**

void PrintInfo(int level, const char *fmt, ...);

**参数：**

- level：入参，日志打印等级，可选项为PRINT_ERROR, PRINT_WARNING, PRINT_STRACE, PRINT_DEBUG
- fmt: 入参，需要输出的字符串

**返回值：**

- 无
