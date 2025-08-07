# 最小安全系统配置指南

可信 (Trusted)
计算指系统可以按照预定的设计和策略运行，并能够低于病毒和一定程度的物理干扰。为了防止外部实体以及有一定权限的内部人员通过物理、远程等方式对系统进行恶意攻击导致系统无法以预期目的运行，本指南通过内核加固选项和系统组件裁剪两个角度对
Linux 操作系统进行加固。

本指南面向 aarch64 架构，其他架构可以参照本指南中的通用加固选项和指南进行修改。

## 内核加固选项

本节介绍内核加固的相关编译选项，我们基于 openeuler 默认选项进行了相关的修改和增强。

相关配置文件可以参考 `openeuler_defconfig`。
将本指南提供的配置文件替换内核构建中的 `.config` 文件，并编译内核后获得加固内核。

### 启动时加固

启动时加固主要指 Linux 内核在启动时针对早期启动时存在的攻击面进行加固或裁剪。

| 选项名称                           | 设置值 | 描述            |
|--------------------------------|-----|---------------|
| CONFIG_EFI_DISABLE_PCI_DMA     | y   | 启动时禁用 PCI DMA |
| CONFIG_RESET_ATTACK_MITIGATION | y   | 重启后清空 RAM     |

### 内核漏洞防利用

内核漏洞防利用指的是通过加固内核代码，限制出现漏洞后攻击者。

| 选项名称                                   | 设置值 | 描述                                  |
|----------------------------------------|-----|-------------------------------------|
| CONFIG_DEBUG_WX                        | y   | 启动时检查内核 W+X 权限段                     |
| CONFIG_GCC_PLUGIN_STACKLEAK            | y   | 离开系统调用前清空内核栈                        |
| CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT | y   | 默认开启内核栈地址随机化                        |
| CONFIG_SHADOW_CALL_STACK               | y   | 开启 Clang Shadow Call Stack 保护控制流完整性 |
| CONFIG_ARM64_PTR_AUTH_KERNEL           | y   | 开启 ARMv8.3-A 指针签名技术，保护控制流完整性        |

### 内核特性裁剪

裁剪高危的内核特性，防止攻击者利用并获取内核信息

| 选项名称                           | 设置值 | 描述                                   |
|--------------------------------|-----|--------------------------------------|
| CONFIG_DEBUG_FS                | n   | 禁用 debugfs                           |
| CONFIG_DEVMEM                  | n   | 禁用 `/dev/mem`                        |
| CONFIG_PROC_KCORE              | n   | 禁用 `/proc/kcore`                     |
| CONFIG_PROC_VMCORE             | n   | 禁用 `/proc/vmcore`                    |
| CONFIG_STACK_TRACER            | n   | 禁用 `/sys/kernel/tracing/stack_trace` |
| CONFIG_KEXEC                   | n   | 禁用 `kexec` 动态加载内核                    |
| CONFIG_KEXEC_FILE              | n   | 禁用 `kexec` 动态加载内核                    |
| CONFIG_USERFAULTFD             | n   | 禁用 `userfaultfd` 系统调用                |
| CONFIG_SECURITY_DMESG_RESTRICT | y   | 限制 `dmesg` 只能被 root 读取               |
| CONFIG_SUNRPC_DEBUG            | n   | 禁用 sunrpc 的 debug 信息输出               |
| CONFIG_MAGIC_SYSRQ             | n   | 禁用 sysrq                             |
| CONFIG_MAGIC_SYSRQ_SERIAL      | n   | 禁用 sysrq                             |

### 内核模块加固

使用更高强度的哈希算法保护内核模块完整性

| 选项名称                     | 设置值 | 描述             |
|--------------------------|-----|----------------|
| CONFIG_MODULE_SIG_FORCE  | y   | 强制内核模块签名       |
| CONFIG_MODULE_SIG_SHA512 | y   | 使用 SHA512 计算哈希 |

### 用户态加固

内核提供了一系列功能用于用户态程序加固。

| 选项名称                         | 设置值   | 描述                                       |
|------------------------------|-------|------------------------------------------|
| CONFIG_DEFAULT_MMAP_MIN_ADDR | 65536 | `mmap` 可映射的起始地址                          |
| CONFIG_SECURITY_LANDLOCK     | y     | 访问控制框架                                   |
| CONFIG_STATIC_USERMODEHELPER | y     | 使用固定的 `usermodehelper` 运行，防止内核拉起恶意程序导致提权 |

## 系统组件裁剪

系统组件裁剪主要通过修改 [oemaker](https://gitee.com/openeuler/oemaker) 配置文件，根据已有的配置进行修改和裁剪，以达到最终构建的
iso 镜像是最小裁剪系统。

相关配置文件可以参考 `normal.xml`。
使用本指南提供的配置文件需要进行以下操作：

1. 下载 `oemaker`：

    ```shell
    yum install oemaker
    ```

2. 使用本指南提供的配置文件替换 `/opt/oemaker/config/aarch64/normal.xml`
3. 根据 [oemaker](https://gitee.com/openeuler/oemaker/tree/master) 文档编译 iso 文件获得裁剪系统

