# Minimum Security System Configuration Guide

Trusted
Computing refers to the ability of a system to operate according to its intended design and policies, while remaining resilient against viruses and a certain degree of physical interference. To prevent malicious attacks from external entities and authorized internal personnel on the system through physical or remote access, which may disrupt the system's intended operation, this guide introduces Linux OS hardening from two perspectives: kernel hardening options and system component tailoring.
 
This guide is oriented to the AArch64 architecture. For other architectures, the general hardening options and guidelines provided here can be adapted as needed.

## Kernel Hardening Options

This section describes the compilation options related to kernel hardening. The default options of openEuler are modified and enhanced.

For details about the configuration file, see `openeuler_defconfig`.
Replace the `.config` file in the kernel build with the configuration file provided in this guide, and then compile the kernel to obtain the hardened kernel.

### Hardening During Startup

Hardening during startup refers to the process of hardening or tailoring the Linux kernel to mitigate attack surfaces present during the early stages of system startup.

| Option                          | Value| Description           |
|--------------------------------|-----|---------------|
| CONFIG_EFI_DISABLE_PCI_DMA     | y   | Disables PCI DMA during startup.|
| CONFIG_RESET_ATTACK_MITIGATION | y   | Clears RAM after restart.    |

### Kernel Vulnerability Anti-Exploitation

Kernel vulnerability anti-exploitation refers to the process of hardening the kernel code to prevent attackers from exploiting vulnerabilities once they occur.

| Option                                  | Value| Description                                 |
|----------------------------------------|-----|-------------------------------------|
| CONFIG_DEBUG_WX                        | y   | Checks the kernel W+X permission segment during startup.                    |
| CONFIG_GCC_PLUGIN_STACKLEAK            | y   | Clears the kernel stack before leaving the system call.                       |
| CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT | y   | Enables kernel stack address randomization by default.                       |
| CONFIG_SHADOW_CALL_STACK               | y   | Enables Clang Shadow Call Stack to protect control flow integrity.|
| CONFIG_ARM64_PTR_AUTH_KERNEL           | y   | Enables the ARMv8.3-A pointer signature technology to protect control flow integrity.       |

### Kernel Feature Tailoring

High-risk kernel features are tailored to prevent attackers from exploiting and obtaining kernel information.

| Option                          | Value| Description                                  |
|--------------------------------|-----|--------------------------------------|
| CONFIG_DEBUG_FS                | n   | Disables debugfs.                          |
| CONFIG_DEVMEM                  | n   | Disables `/dev/mem`.                       |
| CONFIG_PROC_KCORE              | n   | Disables `/proc/kcore`.                    |
| CONFIG_PROC_VMCORE             | n   | Disables `/proc/vmcore`.                   |
| CONFIG_STACK_TRACER            | n   | Disables `/sys/kernel/tracing/stack_trace`.|
| CONFIG_KEXEC                   | n   | Disables the dynamical loading kernel `kexec`.                   |
| CONFIG_KEXEC_FILE              | n   | Disables the dynamical loading kernel `kexec`.                   |
| CONFIG_USERFAULTFD             | n   | Disables the system call `userfaultfd`.               |
| CONFIG_SECURITY_DMESG_RESTRICT | y   | Restricts `dmesg` to be read only by the **root** user.              |
| CONFIG_SUNRPC_DEBUG            | n   | Disables the output of debug information of sunrpc.              |
| CONFIG_MAGIC_SYSRQ             | n   | Disables sysrq.                            |
| CONFIG_MAGIC_SYSRQ_SERIAL      | n   | Disables sysrq.                            |

### Kernel Module Hardening

A stronger hash algorithm is used to protect the integrity of kernel modules.

| Option                    | Value| Description            |
|--------------------------|-----|----------------|
| CONFIG_MODULE_SIG_FORCE  | y   | Forcibly enables the kernel module to verify the signature.      |
| CONFIG_MODULE_SIG_SHA512 | y   | Uses SHA512 to calculate the hash.|

### User-Mode Hardening

The kernel provides a series of functions for user-mode program hardening.

| Option                        | Value  | Description                                      |
|------------------------------|-------|------------------------------------------|
| CONFIG_DEFAULT_MMAP_MIN_ADDR | 65536 | Start address that can be mapped by `mmap`.                         |
| CONFIG_SECURITY_LANDLOCK     | y     | Accesses the control framework.                                  |
| CONFIG_STATIC_USERMODEHELPER | y     | Uses `usermodehelper` (fixed) to prevent the kernel from starting malicious programs, which may cause privilege escalation.|

## System Component Tailoring

System component tailoring is mainly implemented by modifying the [oemaker](https://gitee.com/openeuler/oemaker) configuration file based on the existing configuration. This process ensures that the final
ISO image is the minimum tailored system.

For details about the related configuration file, see `normal.xml`.
To use the configuration file provided in this guide, perform the following operations:

1. Download `oemaker`:

    ```shell
    yum install oemaker
    ```

2. Replace the `/opt/oemaker/config/aarch64/normal.xml` file with the configuration file provided in this guide.
3. Compile the ISO file according to [oemaker](https://gitee.com/openeuler/oemaker/tree/master) to obtain the tailored system.
