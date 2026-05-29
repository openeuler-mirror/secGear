# 安全说明

## 1. Enclave_private.pem 说明

secgear-starterkit 在本地构建 SGX 示例时，会在 build/ 目录中临时生成 Enclave_private.pem，用于 enclave 开发签名和本地验证。

该密钥仅用于示例、教学和 smoke test，不应用于生产环境。

本项目不会将 Enclave_private.pem 作为源码文件提交。

## 2. 生产环境建议

在真实生产环境中，应使用正式密钥管理流程生成、保存和使用 enclave 签名密钥。

生产密钥不应提交到公开代码仓库，也不应打包到示例项目中。

## 3. 构建产物说明

项目构建过程中会生成 build/ 目录、*.so、*.signed.so、host 可执行文件和 CMake 缓存文件。

这些文件属于构建产物，不建议作为源码提交。.gitignore 已对这些文件进行排除。
