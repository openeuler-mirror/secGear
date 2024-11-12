## release v1.0.0
        1. 支持远程证明统一框架，支持快速集成、部署远程证明服务
        2. 新增通过openSession注册共享内存机制，相对ecall方式减少CPU占用率
        3. switchless机制支持配置TA线程绑核，降低频繁调度切换开销，优化REE和TEE业务线程性能
        5. 安全通道支持使用远程证明身份验证
        6. 问题修改/优化：
                - 修改switchless样例编译方式
                - 添加__attribute__((optimize("O0")))来忽略编译优化
                - 使用memset代替explicit_bzero
                - 添加检查内存访问权限来适配ccos
                - 新增配置鲲鹏TA开发者证书方法
                - 解密失败时清除解密数据
                - 优化安全通道验证报告逻辑
                - 签名工具添加无效参数验证
                - 签名工具添加API_LEVEL
                - 修改itrustee_sdk中openssl文件路径

## release v0.2.0
	1. support switchless
	2. support secure channel
	3. some bugfix

## release v0.1.0
        Initialize secGear： support Intel sgx and Arm trustzone(iTrustee OS)
        Libraries: enclave unified lifecycle management APIs, enclave seal data APIs.
        Tools: support codegener/signtools

