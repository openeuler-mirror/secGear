# 使用 secGear 工具

secGear 提供了一套工具集，方便用户开发应用程序。本章介绍相关工具及其使用方法。

## 代码生成工具 codegener

### 简介

secGear codegener 是基于 intel SGX SDK edger8r 开发的工具，用于解析 EDL 文件生成中间 C 代码，即辅助生成安全侧与非安全侧文件互相调用的代码。

secGear codegener 定义的 EDL 文件格式与 intel SGX SDK edger8r 相同，但是不支持 Intel 的完整语法定义：

- 只能在方法中使用 public，不加 public 的函数声明默认为 private
- 不支持从非安全侧到安全侧，以及安全侧到非安全侧的 Switchless Calls
- OCALL（Outside call）不支持部分调用模式（如 cdecl，stdcall，fastcall）

EDL 文件语法为类 C 语言语法，这里主要描述与 C 语言的差异部分：

| 成员                    | 含义                                                         |
| ----------------------- | ------------------------------------------------------------ |
| include "my_type.h"     | 使用外部包含文件中定义的类型                                 |
| trusted                 | 声明 TA（Trusted Application）侧可用安全函数                 |
| untrusted               | 声明 TA 侧可用不安全函数                                     |
| return_type             | 定义返回值类型                                               |
| parameter_type          | 定义参数类型                                                 |
| [in, size = len]       | 对ecall而言，表示该参数需要将数据从非安全侧传入安全侧，ocall反之（指针类型需要使用此参数，其中 size 表示实际使用的 buffer） |
| [out, size = len]       | 对ecall而言，表示该参数需要将数据从安全侧传出到非安全侧，ocall反之（指针类型需要使用此参数，其中 size 表示实际使用的 buffer） |

### 使用说明

#### **命令格式**

codegen 的命令格式如下：

- x86_64 架构：

**codegen_x86_64** \< --trustzone | --sgx > [--trusted-dir \<path> | **--untrusted-dir** \<path>| --trusted | --untrusted ]  edlfile

- ARM 架构：

**codegen_arm64** \< --trustzone | --sgx > [--trusted-dir \<path> | **--untrusted-dir** \<path>| --trusted | --untrusted ]  edlfile

#### **参数说明**

各参数含义如下：

| **参数**               | 是否可选 | 参数含义                                                     |
| ---------------------- | -------- | ------------------------------------------------------------ |
| --trustzone \| --sgx   | 必选     | 只在当前运行命令目录下生成机密计算架构对应接口函数，不加参数默认生成 SGX 接口函数 |
| --search-path \<path>   | 可选     | 用于指定被转译的edl文件所依赖文件的搜索路径   |
| --use-prefix           | 可选     | 用于给代理函数名称加上前缀，前缀名为edl的文件名   |
| --header-only          | 可选     | 指定代码生成工具只生成头文件   |
| --trusted-dir \<path>   | 可选     | 指定生成安全侧辅助代码所在目录，不指定该参数默认为当前路径   |
| --untrusted-dir \<path> | 可选     | 指定生成非安全侧函数辅助代码所在目录                         |
| --trusted              | 可选     | 生成安全侧辅助代码                                           |
| --untrusted            | 可选     | 生成非安全侧辅助代码                                         |
| edlfile                | 必选     | 需要转译的 EDL 文件，例如 hello.edl                          |

#### 示例

- 转译 *helloworld.edl* ，在 *enclave-directory* 下生成安全侧辅助代码，*host-directory* 下生成非安全辅助代码的命令示例如下：

```shell
$ codegen_x86_64 --sgx --trusted-dir enclave-directory --untrusted-dir host-directory helloworld.edl
```

- 转译 *helloworld.edl* ，在当前目录生成安全侧辅助代码，不生成非安全辅助代码的命令示例如下：

```shell
$ codegen_x86_64 --sgx --trusted helloworld.edl
```

- 转译 *helloworld.edl* ，在当前目录生成非安全侧辅助代码，不生成安全辅助代码的命令示例如下：

```shell
$ codegen_x86_64 --sgx --untrusted  helloworld.edl
```

- 转译 *helloworld.edl* ，在当前目录生成安全侧和非安全侧辅助代码的命令示例如下：

```shell
$ codegen_x86_64 --sgx helloworld.edl
```

## 签名工具 sign_tool

### 简介

secGear sign_tool 是一款命令行工具，包含编译工具链和签名工具，用于 enclave 签名。sign_tool 有两种签名形式：

- 单步签名：仅适用于 debug 调试模式
- 两步签名：商用场景。需要从第三方平台或者独立的安全设备获取签名私钥，对  enclave 进行签名

### 使用指导

#### **命令格式**

sign_tool 包含 sign 指令（对 enclave 进行签名）和 digest 指令（生成摘要值）。命令格式为：

**sign_tool.sh -d** [sign | digest] **-x** \<parameter>  **-i** \<file>  **-p** \<file>  **-s** \<file>  [OPTIONS] **–o** \<file> 

#### **参数说明**

| sign 指令参数  | 参数含义                                                       | 是否必选                                      |
| -------------- | -------------------------------------------------------------| --------------------------------------------  |
| -a \<parameter> | api_level，标识 iTrustee TA 的 GP API version，默认为 1        | 可选                                          |
| -c \<file>      | 配置文件                                                       | 可选                                       |
| -d \<parameter> | 指定签名工具要进行的操作（sign 或者 digest）                   | 单步仅执行sign，两步需要先执行digest，再执行sign  |
| -e \<file>      | 设备的公钥证书，用于保护加密 rawdata 的 AES key（iTrustee必需） | 仅 iTrustee 类型必选                         |
| -f \<parameter> | OTRP_FLAG，是否支持 OTRP 标准协议，默认为 0                     | 可选                                         |
| -i \<file>      | 待签名的库文件                                                 | 必选                                         |
| -k \<file>      | 单步签名所需私钥（pem文件）                                     | 仅 SGX 类型必选                              |
| -m \<file>      | 安全配置文件 manifest.txt，由用户自行配置                       | 仅 iTrustee 类型必选                         |
| -o \<file>      | 输出文件                                                      | 必选                                         |
| -p \<file>      | 两步签名所需的签名服务器公钥证书（pem文件）                      | 必选                                         |
| -s \<file>      | 两步签名所需的已签名摘要值                                      | 必选                              |
| -t \<parameter> | TA_TYPA，标识 iTrustee 的 TA 二进制格式，默认为 1               | 可选                                         |
| -x \<parameter> | encalve type（sgx 或 trustzone）                              | 必选                                         |
| -h             | 打印帮助信息                                                   | 可选                                         |

#### **单步签名**

enclave 类型为 SGX，给 test.enclave 签名，输出签名文件 signed.enclave 的示例如下：

```shell
$ sign_tool.sh –d sign –x sgx –i test.enclave -k private_test.pem –o signed.enclave
```

#### **两步签名**

以 SGX 为例，两步签名的操作步骤如下：

1. 生成摘要值

   使用 sign_tool 签名，生成摘要值 digest.data 和临时中间文件 signdata（该文件在生成签名文件时使用，并在签名后自动删除）。参考命令如下：

   ```shell
   $ sign_tool.sh –d digest –x sgx –i input –o digest.data
   ```

2. 将 digest.data 发送至签名机构或平台，并获取对应签名。

3. 使用获取的签名生成签名后的动态库 signed.enclave。

   ```shell
   $ sign_tool.sh –d sign –x sgx–i input  –p pub.pem –s signature –o signed.enclave
   ```

说明：为发布 Intel SGX 支持的正式版本应用，需要申请 Intel 白名单。流程请参考 Intel 文档：<https://software.intel.com/content/www/us/en/develop/download/overview-on-signing-and-whitelisting-for-intel-software-guard-extensions-enclaves.html>
