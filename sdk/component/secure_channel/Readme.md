# 安全通道
## 客户痛点
数据拥有者在请求云上机密计算服务时，需要把待处理数据上传到云上TEE环境中处理，由于TEE没有网络，用户数据需要经过网络先传输到REE，REE接收到数据的明文后，再传入TEE中。用户数据的明文暴露在REE内存中，存在安全风险。

## 解决方案
安全通道是一种结合机密计算远程证明，实现数据拥有者与云上TEE之间安全的密钥协商技术，协商出仅数据拥有者与云上TEE拥有的sessionkey，再通过sessionkey加密用户数据，网络传输的是sessionkey加密后的数据，REE接收到密文数据，再传入TEE中解密，处理。

## 使用方法
安全通道以lib库方式提供，分为客户端、服务端host、服务端enclave三部分，分别由业务程序的客户端、服务端CA、服务端TA调用。
| 模块         | 头文件                      | 库文件                   | 依赖      |
|------------|--------------------------|-----------------------|---------|
| 客户端        | secure_channel_client.h  | libcsecure_channel.so | openssl |
| 服务端host    | secure_channel_host.h    | libusecure_channel.so | openssl |
| 服务端enclave | secure_channel_enclave.h | libtsecure_channel.a| TEE及TEE软件栈     |

### 接口
| 接口名                                                                                                                                          | 所属头文件、库                   | 功能           | 备注 |
|----------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|--------------|----|
| cc_sec_chl_client_init                                                 | secure_channel_client.h libcsecure_channel.so | 安全通道客户端初始化   | 调用前需初始化参数ctx中网络连接和消息发送钩子函数   |
| cc_sec_chl_client_fini                                                                                         | secure_channel_client.h libcsecure_channel.so | 安全通道客户端销毁    | 通知服务端销毁本客户端的信息，销毁本地安全通道信息   |
| cc_sec_chl_client_callback                                              | secure_channel_client.h libcsecure_channel.so | 安全通道协商消息处理函数 | 处理安全通道协商过程中，服务端发送给客户端的消息。在客户端消息接收处调用   |
| cc_sec_chl_client_encrypt | secure_channel_client.h libcsecure_channel.so | 安全通道客户端的加密接口     |  无  |
| cc_sec_chl_client_decrypt | secure_channel_client.h libcsecure_channel.so | 安全通道客户端的解密接口     |  无  |
|  int (*cc_conn_opt_funcptr_t)(void *conn, void *buf, size_t count);                                                                                                                                            |    secure_channel.h                    |    消息发送钩子函数原型          | 由用户客户端和服务端实现，实现中指定安全通道协商消息类型，负责发送安全通道协商消息到对端   |
|  cc_sec_chl_svr_init                                                                                                                                            |  secure_channel_host.h  libusecure_channel.so                    |  安全通道服务端初始化            | 调用前需初始化ctx中enclave_ctx   |
|  cc_sec_chl_svr_fini                                                                                                                                            |   secure_channel_host.h  libusecure_channel.so                    |  安全通道服务端销毁            |  销毁安全通道服务端以及所有客户端信息  |
|  cc_sec_chl_svr_callback                                                                                                                                            |  secure_channel_host.h  libusecure_channel.so                     |  安全通道协商消息处理函数            | 处理安全通道协商过程中，客户端发送给服务端的消息。在服务端消息接收处调用，调用前需初始化与客户端的网络连接和发送消息函数，详见[样例](https://gitee.com/openeuler/secGear/blob/master/examples/secure_channel/host/server.c#:~:text=conn_ctx.conn_kit.send)。   |
| cc_sec_chl_enclave_encrypt                                                                                                                                             |    secure_channel_enclave.h libtsecure_channel.a                   | 安全通道enclave中的加密接口             |  无  |
|   cc_sec_chl_enclave_decrypt                                                                                                                                           |   secure_channel_enclave.h libtsecure_channel.a                    | 安全通道enclave中的解密接口             |  无  |

### 注意事项
安全通道仅封装密钥协商过程、加解密接口，不建立网络连接，协商过程复用业务的网络连接。其中客户端和服务端的网络连接由业务建立和维护，在安全通道客户端和服务端初始化时传入消息发送钩子函数和网络连接指针，详见[安全通道样例](https://gitee.com/openeuler/secGear/tree/master/examples/secure_channel)。

