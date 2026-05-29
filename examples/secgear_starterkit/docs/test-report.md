# secgear-starterkit 测试报告

## 1. 测试环境

- 操作系统：openEuler 22.03 LTS
- 架构：x86_64
- CPU：Intel Xeon Platinum 8369B
- SGX CPU 特征：sgx / sgx_lc
- SGX 设备节点：
  - /dev/sgx_enclave
  - /dev/sgx_provision

## 2. 自动化测试

测试命令：

    bash tests/run_all.sh

测试覆盖三条链路：

1. templates/basic 基础模板构建与签名；
2. examples/seal_data 样例构建与签名；
3. scripts/init.sh 生成的新项目独立构建与签名。

测试结果：

    All smoke tests passed.

## 3. basic 样例 SGX 真机运行验证

测试命令：

    bash scripts/run.sh

运行结果：

    message from enclave: hello from secGear starterkit
    sum from enclave: 42

结论：

basic 样例已在 SGX 真机环境中成功创建并执行 enclave。

## 4. seal_data 样例 SGX 真机运行验证

测试命令：

    bash scripts/run_seal_data.sh

运行结果：

    sealed result: ENC:secret-for-demo
    sealed length: 20
    unsealed result: secret-for-demo
    unsealed length: 16

结论：

seal_data 样例已完成 SGX 环境下的端到端运行验证。当前版本采用稳定占位实现，用于展示 StarterKit 在样例扩展、接口封装和运行链路上的能力。

## 5. 总体结论

secgear-starterkit 已在支持 SGX 的 openEuler 22.03 LTS 环境完成自动化测试和真机运行验证。

项目当前已经具备：

- secGear 基础模板能力；
- 第二独立样例能力；
- 一键脚手架生成能力；
- 自动化 smoke test 能力；
- SGX 真机运行验证结果。

测试结论：通过。
