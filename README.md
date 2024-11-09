<img src="docs/logo.png" alt="secGear" style="zoom:100%;" />

secGear
============================

介绍
-----------

secGear是开源的机密计算项目，致力于提供简单、易用的机密计算软件栈及解决方案，降低机密计算的使用门槛，推动机密计算生态发展。

组件
-----------
| 目录 | 用途    |
|-----------|-----------|
| [src](./src/)       | 统一SDK：屏蔽Intel SGX、鲲鹏Trustzone以及RISC-V蓬莱TEE等SDK差异，提供统一API，实现不同架构共源码，提供代码生成工具，使用户聚焦业务，提升开发效率。开发可参考[HelloWorld开发流程](./docs/HelloWorld开发流程和特性使用指南.md)。|
| [component](./component)   | 安全组件：提供通用安全组件货架，支持传统lib库集成方式快速集成，构建机密计算解决方案。|
| [service](./service)     | 提供通用安全服务，如[远程证明统一框架](https://gitee.com/openeuler/secGear/blob/master/service/attestation/README.md) ，支持快速集成、部署远程证明服务。|


Quick start
----------------

### Quick start with Intel SGX
#### 环境要求
- 处理器：需要支持 Intel SGX （Intel Software Guard Extensions）功能
- 操作系统：openEuler 21.03、openEuler 20.03 LTS SP2或更高版本

#### Build and Run
```
// install build require
sudo yum install -y cmake ocaml-dune linux-sgx-driver sgxsdk libsgx-launch libsgx-urts intel-sgx-ssl-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// build secGear and examples
cd secGear
source /opt/intel/sgxsdk/environment && source environment
mkdir debug && cd debug && cmake .. && make && sudo make install

// run helloworld
./examples/helloworld/host/secgear_helloworld
```

### Quick start with ARM TrustZone
#### 环境搭建
- 参考[鲲鹏官网](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/fg-tz/kunpengtrustzone_04_0006.html)
- 操作系统：openEuler 21.03、openEuler 20.03 LTS SP2或更高版本

#### Build and Run
```
// install build require
sudo yum install -y cmake ocaml-dune itrustee_sdk-devel openssl-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// build secGear and examples
cd secGear
source environment
mkdir debug && cd debug && cmake -DENCLAVE=GP .. && make && sudo make install

// run helloworld
/vendor/bin/secgear_helloworld
```

如何贡献
----------------

我们非常欢迎新贡献者加入到项目中来，也非常高兴能为新加入贡献者提供指导和帮助。在您贡献代码前，需要先签署[CLA](https://www.openeuler.org/zh/blog/2022-11-25-cla/CLA%E7%AD%BE%E7%BD%B2%E6%B5%81%E7%A8%8B.html)。


如果您有任何疑问或讨论，请通过[issue](https://gitee.com/openeuler/secGear/issues)或发送邮件到dev@openeuler.org和我们进行联系。

- 会议

	每个月单周周四下午14:30-15:30召开SIG组例会，您可通过订阅[dev@openeuler.org](https://mailweb.openeuler.org/postorius/lists/dev@openeuler.org/)方式收到例会会议通知。

License
----------------
Mulan Permissive Software License Version 2
