# secgear-starterkit

## 1. 项目简介

secgear-starterkit 是一个面向 openEuler secGear 的机密应用 StarterKit，提供项目脚手架、真实样例和自动化测试模板。

项目目标是降低 secGear 应用开发门槛，补齐从官方最小样例到可复用工程模板之间的工程化空档，帮助开发者快速完成 secGear 工程初始化、EDL 代理代码生成、host/enclave 构建与签名、自动化 smoke test 验证以及新项目脚手架生成。

## 2. 项目价值

openEuler secGear 已经提供机密计算基础能力，但开发者在创建 secGear 应用时，仍需要手动处理 EDL、代理代码生成、host/enclave 构建、enclave 签名、SGX 环境运行验证等流程。

本项目将这些流程整理为可复用模板、样例工程、脚手架生成器和自动化测试入口，帮助开发者更快启动新的 secGear 应用项目。

## 3. 功能特性

- 提供 templates/basic 最小 secGear 工程模板；
- 提供 examples/seal_data 独立样例；
- 提供 scripts/init.sh，一键生成新的 secGear 项目；
- 提供自动化 smoke test；
- 提供统一测试入口 tests/run_all.sh；
- 已在支持 SGX 的 openEuler 22.03 LTS 环境完成真机验证。

## 4. 项目结构

secgear-starterkit/
├── templates/
│   └── basic/
├── examples/
│   └── seal_data/
├── scripts/
│   ├── build.sh
│   ├── init.sh
│   ├── run.sh
│   └── run_seal_data.sh
├── tests/
│   ├── run_all.sh
│   └── smoke/
├── docs/
├── .gitignore
└── README.md

## 5. 环境要求

- openEuler 22.03 LTS
- x86_64
- 支持 Intel SGX 的运行环境
- 系统存在以下 SGX 设备节点：
  - /dev/sgx_enclave
  - /dev/sgx_provision
- 已安装 secGear 相关依赖

## 6. 快速开始

### 6.1 运行全量 smoke test

执行：

    bash tests/run_all.sh

预期结果：

    All smoke tests passed.

### 6.2 运行 basic 样例

执行：

    bash scripts/run.sh

预期结果：

    message from enclave: hello from secGear starterkit
    sum from enclave: 42

### 6.3 运行 seal_data 样例

执行：

    bash scripts/run_seal_data.sh

预期结果：

    sealed result: ENC:secret-for-demo
    sealed length: 20
    unsealed result: secret-for-demo
    unsealed length: 16

## 7. 生成新项目

执行：

    bash scripts/init.sh ci_demo_app

生成的新项目位于：

    generated/ci_demo_app

可进入该目录进行独立构建验证。

## 8. 测试说明

项目提供统一测试入口：

    bash tests/run_all.sh

该入口覆盖三条链路：

1. templates/basic 基础模板构建与签名；
2. examples/seal_data 样例构建与签名；
3. scripts/init.sh 生成的新项目独立构建与签名。

详细测试报告见：

    docs/test-report.md

安全说明见：

    docs/security-note.md

## 9. openEuler 适配说明

本项目已在支持 SGX 的 openEuler 22.03 LTS 环境完成验证，验证内容包括：

- openEuler 系统环境检查；
- SGX CPU 特征检查；
- SGX 设备节点检查；
- host/enclave 构建；
- enclave 签名；
- SGX 真机运行；
- 自动化 smoke test。

## 10. 当前限制

当前版本中，seal_data 样例采用稳定占位实现，重点用于展示 StarterKit 在样例扩展、接口封装和端到端运行链路上的能力。

后续可以继续扩展为更真实的机密数据处理样例。

## 11. 社区贡献价值

本项目可作为 openEuler secGear 的工程模板、示例集合和测试基线，帮助开发者更快理解和使用 secGear 开发机密计算应用。

## 12. License

本示例随 secGear 项目采用 Mulan PSL v2 许可证。
