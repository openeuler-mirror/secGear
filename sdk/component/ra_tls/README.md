# ra-tls

secGear支持ra-tls，基于远程证明服务，在机密环境与数据提供方之间建立TLS连接，确保数据可靠传输。

# 依赖环境
远程证明服务AS，AA服务，服务配置参考service/attestation/README.md

# 编译和安装
执行如下指令编译
cd component/ra_tls
mkdir build
cmake ../
//也可以指定默认的TLS库，并开启Debug模式
cmake ../ -DCMAKE_BUILD_TYPE=Debug -DTLS_LIB=OPENSSL
make
make install

# 运行示例
在 examples/ra_tls 目录下执行
mkdir build
cd build
cmake ../
make
./server
./client