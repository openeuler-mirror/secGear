# 安全通道样例

本样例分为客户端、服务端host、服务端enclave三部分。其中基于单线程和多线程两种场景，实现了两种客户端。
## 目录结构

```
├── client                     // 单线程客户端
│   ├── client.c
│   └── CMakeLists.txt
├── client_with_recv_thread   // 多线程客户端：主线程、独立消息接收线程
│   ├── client.c
│   └── CMakeLists.txt
├── CMakeLists.txt
├── enclave                   // 服务端TA    
│   ├── CMakeLists.txt
│   ├── config_cloud.ini
│   ├── enclave.c
│   ├── Enclave.config.xml
│   ├── Enclave.lds
│   └── manifest.txt
├── host                    // 服务端CA
│   ├── CMakeLists.txt
│   └── server.c
├── sc_demo.edl             // CA与TA之间的接口
└── usr_msg.h               // 由用户基于业务的网络连接、钩子函数原型实现的发送消息钩子函数。
```

## Quick Start
### Intel SGX

```
// intall build require
sudo yum install -y cmake ocaml-dune linux-sgx-driver sgxsdk libsgx-launch libsgx-urts intel-sgx-ssl

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// build secGear and examples
cd secGear
source /opt/intel/sgxsdk/environment && source environment
mkdir debug && cd debug && cmake -DSSL_PATH=/opt/intel/sgxssl .. && make && sudo make install

// start server
./bin/sc_server

// start client
./bin/sc_client
```
### Arm Trustzone

```
// intall build require depends openEuler 23.03 repo
sudo yum install -y cmake ocaml-dune itrustee_sdk-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// build secGear and examples
cd secGear
source environment
mkdir debug && cd debug && cmake -DENCLAVE=GP .. && make && sudo make install

// start server
/vendor/bin/sc_server

// start client 
/vendor/bin/sc_client
```


