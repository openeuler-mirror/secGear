Host侧安全通道cffi接口定义：component/secure_channel/host/python/sec_chl_wrapper.py
由enclave的edl文件生成的*.h和*.c文件需要拷贝到component/secure_channel/host/python/

示例执行：
1、编译生成so
    python sec_chl_wrapper.py

2、执行客户端示例
    /usr/bin/python server.py