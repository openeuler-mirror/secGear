# OS Security Hardening Configuration Guide

This guide provides tools and methods for security hardening on the openEuler OS. It includes suggestions on system configuration and automation scripts, aiming to help users improve system security.

## Directory Structure

```sh
secTools/
├── README.md: this guide
├── secharden.spec: RPM package specification file of the tool attached to this guide
├── secharden: system hardening tool attached to this guide
├── conf: configuration file of the system hardening tool
├── docs: minimum security system configuration guide, including the system kernel configuration file and minimum tailoring configuration
```

## secharden

secharden is a Python-based system hardening framework used to manage and apply various security hardening rules.
It provides a flexible way to enhance system security and supports the configuration and execution of multiple hardening rules.

### Installation

For details about how to build secharden,
[build_doc](https://docs.openeuler.org/zh/docs/24.03_LTS_SP2/server/development/application_dev/building_an_rpm_package.html).

1. Initialize the **rpmbuild** directory:

    ```shell
    rpmdev-setuptree
    ```

2. Download the secharden source code:

    ```shell
    git clone https://gitee.com/openeuler/secGear
    # Associate the source code directory with the **SOURCES** directory of rpmbuild using a soft link for subsequent RPM package building.
    rm -rf $HOME/rpmbuild/SOURCES
    ln -s ./secGear/secharden $HOME/rpmbuild/SOURCES
    ```

3. Build:

    ```shell
    rpmbuild -ba $HOME/rpmbuild/SOURCES/secharden.spec
    ```

After the build is complete, you can find the built RPM package in `$HOME/rpmbuild/RPMS/noarch/secharden-<Version>.noarch.rpm`.
You can run the `dnf install` command to install the RPM package.

```shell
sudo dnf install $HOME/rpmbuild/RPMS/noarch/secharden-<Version>.noarch.rpm
```

### Usage

> Using secharden requires the **root** permission. Therefore, ensure that you run the commands as the **root** user or using `sudo`.

secharden provides a command line tool. You can run the following command to apply security hardening rules:

```shell
secharden apply
```

**Precautions**:

1. After `secharden apply` is used to apply the configuration file hardening, deleting the corresponding hardening items and using `secharden apply` again cannot clear the configuration that has taken effect.
2. Security hardening operations are logged in the `/var/log/secharden/secharden.log` file.

> For details about how to use secharden, see [command_line_parameters](secharden/README.md).

#### Configuration File Description

**Configuration File Directory Structure**

By default, secharden searches for the configuration file in the `/etc/secharden` directory. This directory contains a `secharden.conf` file and a `secharden.conf.d`
directory.

The `secharden.conf` file defines the global configuration and the enabling status of rules.
All the rules described in [Built-in Security Protection Capabilities of secharden](#built-in-security-protection-capabilities-of-secharden) can be configured in this file. You can enable or disable specific security hardening rules by editing this file.

You are advised to create a sub-configuration file in the `secharden.conf.d` directory. The configuration files in this directory will overwrite the configuration items in `secharden.conf` based on their priorities.
 The configuration files in this directory must meet the following requirements:

- The configuration file is named in the format of `<Priority>-<Name>.conf`, for example, `01-disable_ptrace.conf`. `<Priority>`
  is an integer greater than 0, indicating the loading priority of the configuration file. A smaller value indicates a higher priority.

**Configuration File Format**

The configuration file is in YAML format and contains a dictionary with the rule ID as the key and parameters with the value as the rules. The following is an example:

```yaml
int.01:
  enabled: true
int.03:
  selinux_tags:
    - user_home_t
    - var_log_t
net.01:
  enabled: false
net.02:
```

The preceding configuration file indicates that the `int.01`, `int.03`, and `net.02` rules are enabled, the `net.01` rule is explicitly disabled, and the SELinux label is specified for the `int.03` rule.

In addition to the parameters defined by each rule, each rule has a special `enabled` parameter that is used to enable or disable the rule. If the `enabled` parameter is not explicitly specified in a rule,
the rule is enabled by default. You can disable a rule by setting `enabled: false`. The following is an example:

```yaml
int.01:
  enabled: false
```

**Rule Help Information**

You can obtain the corresponding rule information from the help document provided by `secharden`.

Run the following command to obtain the rule list:

```shell
secharden list
```

You can also obtain the detailed description of a rule. For example, run the following command to obtain the information about the `int.03` rule:

```shell
secharden help int.03
```

### Built-in Security Protection Capabilities of secharden

secharden provides a series of security hardening rules, which can be managed and applied through configuration files. Each rule contains specific security measures. You can enable or disable these rules as required.

For details about the rules, see [os_security_configuration_tools](secharden/src/secharden/tools/README.md).

#### Full-Stack Integrity Hardening

The system is vulnerable to tampering at any stage of its startup and running. Tampering with the system or service software will make the system running untrusted. Full-stack integrity hardening performs security verification throughout the lifecycle to detect whether a tampering attack occurs. Currently, the following integrity security configurations are supported:

| ID     | Hardening Rule         | Protection Scope| Protection Period |
|--------|---------------|------|-------|
| int.01 | Enable the kernel module signature.     | Kernel modules| System startup|
| int.02 | Enable the DIM dynamic measurement kernel.| Kernel code| System runtime|
| int.03 | Enable IMA to measure key files.| User files| Service loading|

According to [secure_boot](https://docs.openeuler.openatom.cn/zh/docs/24.03_LTS_SP2/server/security/cert_signature/secure_boot.html),
verify the integrity of the loaded system image during startup to implement full-lifecycle system anti-tampering.

Currently, int.01 and int.02 have been enabled in the `secharden.conf` configuration file by using the following fields:

```yaml
int.01:
int.02:
```

> Note: The int.02 rule depends on the DIM module. You need to run the following command to install the DIM module:
> 
> ```shell
> sudo yum install dim dim_tools
> ```

To implement full-stack integrity hardening by using the int.03 rule, perform the following steps:

1. Set the IMA label.

   secharden uses SELinux labels to distinguish the scope of user files that require IMA protection. You can run the following command to associate a file with an SELinux label:

   ```sh
   semanage fcontext -a -t $type $file
   restorecon -v $file
   ```

2. Enable rules.

   Create the `/etc/secharden/secharden.conf.d/01-ima_tags.conf` configuration file with the following content:

    ```yaml
    int.03:
      selinux_tags:
        - <Your SELinux label, for example, user_home_t>
    ```

After the int.03 rule is configured, run the `secharden apply` command to apply all the rules in this section.

#### Kernel Hardening

Kernel hardening is used to enhance kernel security and prevent attackers from exploiting kernel vulnerabilities. Currently, the following security configurations are supported:

| ID      | Hardening Rule         | Protection Scope|
|---------|---------------|------|
| kern.01 | Enables BPF hardening.  | Kernel modules|
| kern.02 | Enables kernel ASLR.    | Kernel code|
| kern.03 | Ensures that the kernel exits directly after an error is triggered.| Kernel code|

Currently, the preceding rules have been enabled in the `secharden.conf` configuration file using the following fields:

```yaml
kern.01:
kern.02:
kern.03:
```

You can directly run the `secharden apply` command to apply all the rules in this section. No additional configuration is required.

#### Login Authentication

Login authentication is used to protect the system login authentication process and prevent attackers from obtaining user credentials through brute force cracking. Currently, the following security configurations are supported:

| ID       | Hardening Rule                      | Protection Scope|
|----------|----------------------------|------|
| login.01 | Disables login with empty passwords.                   | SSH  |
| login.02 | Disables the use of PermitUserEnvironment.| SSH  |
| login.03 | Disables SSH login for the **root** user.       | SSH  |
| login.04 | Disables the TCP forwarding function of SSH.         | SSH  |
| login.05 | Disables the X11 forwarding function.       | SSH  |
| login.06 | Disables the SysRq key.              | Physical machine |
| login.07 | Disables tcp_timestamps.       | Network  |
| login.08 | Sets the maximum number of authentication attempts.                  | SSH  |

Currently, the preceding rules have been enabled in the `secharden.conf` configuration file using the following fields:

```yaml
login.01:
login.02:
login.03:
login.04:
login.05:
login.06:
login.07:
login.08:
```

You can directly run the `secharden apply` command to apply all the rules in this section. No additional configuration is required.

#### Network Protection

Network protection is used to protect system network connections and prevent attackers from launching attacks through the network. Currently, the following security configurations are supported:

| ID     | Hardening Rule             | Protection Scope|
|--------|-------------------|------|
| net.01 | Disables ICMP redirection packets.    | Network  |
| net.02 | Forbids the system to respond to ICMP broadcast packets. | Network  |
| net.03 | Disables IP forwarding.         | Network  |
| net.04 | Disables the ARP proxy.      | Network  |
| net.05 | Disables the source packet routing.          | Network  |
| net.06 | Discards forged ICMP packets.    | Network  |
| net.07 | Enables the firewall service.          | Network  |
| net.08 | Enables reverse address filtering.         | Network  |
| net.09 | Enables TCP-SYN cookie.| Network  |

Currently, the preceding rules have been enabled in the `secharden.conf` configuration file using the following fields:

```yaml
net.01:
net.02:
net.03:
net.04:
net.05:
net.06:
net.07:
net.08:
net.09:
```

You can directly run the `secharden apply` command to apply all the rules in this section. No additional configuration is required.

#### Permission Minimization

Permission minimization is used to restrict the permissions of users and processes in the system, preventing attackers from obtaining higher permissions through privilege escalation. Currently, the following security configurations are supported:

| ID      | Hardening Rule    | Protection Scope|
|---------|----------|------|
| priv.01 | Minimizes file permissions. | User files|
| priv.02 | Enables link file protection.| User files|

Currently, the preceding rules have been enabled in the `secharden.conf` configuration file using the following fields:

```yaml
priv.01:
priv.02:
```

You can directly run the `secharden apply` command to apply all the rules in this section. No additional configuration is required.

### Enabling Security Services

Security services are enabled to ensure that the security services in the system are running properly and prevents attackers from disabling the security services to reduce the system security. Currently, the following security configurations are supported:

| ID      | Hardening Rule                 | Protection Scope|
|---------|-----------------------|------|
| serv.01 | Enables the rsyslog service.        | Logs  |
| serv.02 | Enabling the Enforce Mode for SELinux| User files|

Currently, the preceding rules have been enabled in the `secharden.conf` configuration file using the following fields:

```yaml
serv.01:
serv.02:
```

You can directly run the `secharden apply` command to apply all the rules in this section. No additional configuration is required.

#### Restricting High-Risk System Functions

High-risk system functions are restricted to prevent attackers from abusing system functions to obtain higher permissions or perform other malicious operations. Currently, the following security configurations are supported:

| ID     | Hardening Rule         | Protection Scope|
|--------|---------------|------|
| sys.01 | Configures the dmesg access permission.| Kernel modules|
| sys.02 | Disables the kexec function.| Kernel modules|
| sys.03 | Restricts the read permission on kernel symbols.   | Kernel modules|
| sys.04 | Restricts the ptrace scope. | Kernel modules|
| sys.05 | Disables uncommon network services.    | Kernel modules|

Currently, the preceding rules have been enabled in the `secharden.conf` configuration file using the following fields:

```yaml
sys.01:
sys.02:
sys.03:
sys.04:
sys.05:
```

You can directly run the `secharden apply` command to apply all the rules in this section. No additional configuration is required.

## Minimum Security System Configuration Guide

The `docs` directory contains the minimum secure system configuration guide, which includes the following contents:

- [configuration_guide](docs/README.md)
- [system_kernel_configuration_file](docs/openeuler_defconfig)
- [minimum_configuration_file_for_image_building](docs/normal.xml)

> For details, see [configuration_guide](docs/README.md).
