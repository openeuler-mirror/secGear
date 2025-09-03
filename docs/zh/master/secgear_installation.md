# 安装 secGear

## ARM环境

### 环境要求

#### 硬件环境

| 项目   | 版本                                                |
| ------ | --------------------------------------------------- |
| 服务器 | TaiShan 200服务器（型号2280）                       |
| 主板   | 鲲鹏主板                                            |
| BMC    | 1711单板（型号BC82SMMAB），固件版本不低于3.01.12.49 |
| CPU    | 鲲鹏920处理器（型号7260、5250、5220）               |
| 机箱   | 不限，建议8盘或12盘                                 |

> [!NOTE]说明
> 要求服务器已经预置TrustZone特性套件，即预装TEE OS、TEE OS启动密钥、BMC、BIOS和License许可证。
> 普通服务器无法仅通过升级BMC、BIOS、TEE OS固件实现TrustZone特性使能。
> 带TrustZone特性的服务器出厂默认特性关闭，请参考BIOS设置使能服务器TrustZone特性。

#### 操作系统

openEuler 20.03 LTS SP2及以上

openEuler 25.03

openEuler 22.03 LTS及以上

### 环境准备

参考鲲鹏官网[环境要求](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/trustzone/fg/kunpengtrustzone_20_0018.html)和[搭建步骤](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/trustzone/fg/kunpengtrustzone_20_0019.html)。

### 安装操作

1. 配置openEuler yum源，在线yum源或通过ISO挂载配置本地yum源，配置在线源如下（仅以22.03-LTS举例，其他版本需要使用版本对应的yum源）。

   ```shell
   vi /etc/yum.repo/openEuler.repo 
   [osrepo]
   name=osrepo
   baseurl=http://repo.openeuler.org/openEuler-22.03-LTS/everything/aarch64/
   enabled=1
   gpgcheck=1
   gpgkey=http://repo.openeuler.org/openEuler-22.03-LTS/everything/aarch64/RPM-GPG-KEY-openEuler
   ```

2. 安装secGear。

   ```shell
   #安装编译工具
   yum install cmake ocaml-dune
   
   #安装secGear
   yum install secGear-devel
   
   #检查是否安装成功。命令和回显如下表示安装成功。
   rpm -qa | grep -E 'secGear|itrustee|ocaml-dune'
   itrustee_sdk-xxx
   itrustee_sdk-devel-xxx
   secGear-xxx
   secGear-devel-xxx
   ocaml-dune-xxx
   ```

## X86环境

### 环境要求

#### 硬件环境

支持Intel SGX（Intel Software Guard Extensions）特性的处理器。

#### 操作系统

openEuler 20.03 LTS SP2及以上

openEuler 25.03

openEuler 22.03 LTS及以上

### 环境准备

购买支持Intel SGX特性设备，参考对应设备BIOS配置手册，开启SGX特性。

### 安装操作

1. 配置openEuler yum源，在线yum源或通过ISO挂载配置本地yum源，配置在线源如下（仅以22.03-LTS举例，其他版本需要使用版本对应的yum源）。

   ```shell
   vi openEuler.repo 
   [osrepo]
   name=osrepo
   baseurl=http://repo.openeuler.org/openEuler-22.03-LTS/everything/x86_64/
   enabled=1
   gpgcheck=1
   gpgkey=http://repo.openeuler.org/openEuler-22.03-LTS/everything/x86_64/RPM-GPG-KEY-openEuler
   ```

2. 安装secGear。

   ```shell
   #安装编译工具
   yum install cmake ocaml-dune
   
   #安装secGear
   yum install secGear-devel
   
   #检查是否安装成功。命令和回显如下表示安装成功。
   rpm -qa | grep -E 'secGear|ocaml-dune|sgx'
   secGear-xxx
   secGear-devel-xxx
   ocaml-dune-xxx
   libsgx-epid-xxx
   libsgx-enclave-common-xxx
   libsgx-quote-ex-xxx
   libsgx-aesm-launch-plugin-xxx
   libsgx-uae-service-xxx
   libsgx-ae-le-xxx
   libsgx-urts-xxx
   sgxsdk-xxx
   sgx-aesm-service-xxx
   linux-sgx-driver-xxx
   libsgx-launch-xxx
   ```
