# secGear支持擎天Enclave
## 简介
[擎天Enclave](https://support.huaweicloud.com/productdesc-ecs/ecs_03_1421.html)是华为云推出的一个可信执行环境，secGear作为机密计算统一开发框架，现支持擎天Enclave。
## Quick start
### 环境要求：
- 支持Enclave的华为云实例
- 已安装qingtian软件栈
### Build and Run

```
// config hce repo and install secGear-devel
sudo yum install -y secGear-devel

// download secGear example
git clone https://gitee.com/openeuler/secGear.git

// build examples
cd secGear

// 当前默认不编译example，需要修改CMakeLists.txt，打开如下行注释，开启编译example
vim CMakeLists.txt
#add_subdirectory(examples) 

source environment
mkdir debug && cd debug && cmake -DCC_QT=ON .. && make && cd examples/helloworld && sudo make install

// run helloworld
./examples/helloworld/host/secgear_helloworld
```
## 支持接口
- host侧接口

| 接口  | 接口说明  |
|---|---|
| cc_enclave_create()  |  用于创建安全侧的安全进程，针对安全区进程进行内存和相关上下文的初始化，当用户不通过feature传入自定义enclave配置时，使用默认配置（cpu:2, 内存:4*size(.eif)大小，按256M对齐向上取整, cid：4，如果cid已存在，会自动递增）。用户也可通过feature自定义配置enclave的cpu、内存及cid |
| cc_enclave_destroy()  | 用于销毁相关安全进程，对安全内存进行释放  |
| cc_get_ra_report  | 获取远程证明报告  |

- enclave侧接口

| 接口                           | 接口说明             |
|------------------------------|------------------|
| cc_enclave_generate_random() | 用于在安全侧生成密码安全的随机数,cc_enclave_create成功返回后0.5S以上再调用此接口,否则可能会失败 |

- 工具接口

| 接口           | 接口说明                           |
|--------------|--------------------------------|
| sign_tool.sh | 对enclave进行签名                   |
| codegen      | 代码生成工具，根据edl文件编译生成非安全侧与安全侧交互代码 |


## 约束限制
- 一个CA进程只能加载一个TA
- 单个擎天VM， 最大能够同时运行两个CA进程
- ecall调用的所有参数数据长度总和不超过1M


## 第三方依赖
[Qingtian SDK](https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian/tree/master)
