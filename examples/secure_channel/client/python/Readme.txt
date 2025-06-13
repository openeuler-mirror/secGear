客户端安全通道cffi接口定义：component/secure_channel/client/python/sec_chl_wrapper.py
由enclave的edl文件生成的*.h文件需要拷贝到component/secure_channel/client/python/

示例执行：
1、编译生成so
    python sec_chl_wrapper.py

2、执行客户端示例（需要先启动安全通道host侧服务程序）
    python client.py