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
sudo yum install -y cmake ocaml-dune linux-sgx-driver sgxsdk libsgx-launch libsgx-urts intel-sgx-ssl secGear-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// build example secure channel
cd secGear/examples/secure_channel
source /opt/intel/sgxsdk/environment
mkdir debug && cd debug && cmake .. && make && sudo make install

// start server
./bin/sc_server

// start client
./bin/sc_client
```
### Arm Trustzone
#### 环境准备
[参照远程证明环境准备](https://gitee.com/houmingyong/secGear/tree/master/examples/remote_attest#%E7%8E%AF%E5%A2%83%E5%87%86%E5%A4%87)   
与远程证明环境准备有两点差别
1. 将/vendor/bin/sc_server修改到QTA的源码中
2. 将Huawei IT Product CA.pem上传到环境 secGear/examples/secure_channel/build/目录下

#### 编译运行secGear样例

```
// intall build require depends openEuler 23.03 repo
sudo yum install -y cmake ocaml-dune itrustee_sdk-devel secGear-devel

// clone secGear repository
git clone https://gitee.com/openeuler/secGear.git

// 配置TA开发者证书
cd secGear/examples/secure_channel
// 将TA开发者证书对应的manifest.txt拷贝到样例enclave目录下
cp -rf {manifest.txt}  enclave/
// 将TA开发者证书的路径配置到config_cloud.ini文件中
vim enclave/config_cloud.ini 
修改encryptKey、signKey、configPath三个路径

// enable sign TA, 在enclave/CMakeLists.txt文件中放开以下三行代码注释
add_custom_command(TARGET ${PREFIX}
    POST_BUILD
    COMMAND bash ${SIGN_TOOL} -d sign -x trustzone -i ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${PREFIX}.so -c ${CMAKE_CURRENT_SOURCE_DIR}/manifest.txt -m ${CMAKE_CURRENT_SOURCE_DIR}/config_cloud.ini -o ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${OUTPUT})

// build example secure channel
cd secGear/examples/secure_channel
mkdir build && cd build && cmake -DENCLAVE=GP .. && make && sudo make install

// start server
/vendor/bin/sc_server

// config basevalue.txt
// edit basevalue.txt to overwrite taid img_hash mem_hash, the img_hash and mem_hash comes from /opt/itrustee_sdk/build/signtools/hash_uuid.txt

// start client 
/vendor/bin/sc_client
```


