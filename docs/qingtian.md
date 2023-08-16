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
source environment
mkdir debug && cd debug && cmake -DCC_QT=ON .. && make && cd examples/helloworld && sudo make install

// run helloworld
./examples/helloworld/host/secgear_helloworld
```

## 约束限制
- 一个CA进程只能加载一个TA
- 单个擎天VM， 最大能够同时运行两个CA进程
- ecall调用的所有参数数据长度总和不超过1M


## 第三方依赖
[Qingtian SDK](https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian/tree/master)