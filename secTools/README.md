# 安全 OS 加固配置指南

本指南提供了在 openEuler 操作系统上进行安全加固的工具和方法。它包括了对系统配置的建议和自动化脚本，旨在帮助用户提高系统的安全性。

## 目录结构

```
secTools/
├── README.md: 本文档
├── secharden.spec：本指南随附工具的 RPM 包规范文件
├── secharden：本指南随附的系统加固工具
├── conf：包含系统加固工具的配置文件
├── docs：最小安全系统配置指南，包含系统内核的配置文件以及最小化裁剪配置
```

## secharden

secharden 是一个基于 python 的系统加固框架，用于管理和应用各种安全加固规则。
它提供了一个灵活的方式来增强系统的安全性，支持多种加固规则的配置和执行。

### 安装

本节描述的 secharden 构建可参考
[openeuler rpm 包构建文档](https://docs.openeuler.org/zh/docs/24.03_LTS_SP2/server/development/application_dev/building_an_rpm_package.html)。

1. 初始化 rpmbuild 目录：

    ```shell
    rpmdev-setuptree
    ```

2. 下载 secharden 源码：

    ```shell
    git clone https://gitee.com/openeuler/secGear
    # 将源码目录通过软链接的形式关联到 rpmbuild 的 SOURCES 目录下，以便后续构建 rpm 包时使用
    rm -rf $HOME/rpmbuild/SOURCES
    ln -s ./secGear/secharden $HOME/rpmbuild/SOURCES
    ```

3. 构建：

    ```shell
    rpmbuild -ba $HOME/rpmbuild/SOURCES/secharden.spec
    ```

构建后，可以在 `$HOME/rpmbuild/RPMS/noarch/secharden-<版本>.noarch.rpm` 找到构建完成的 rpm 包。
该 rpm 包可以直接使用 `dnf install` 命令安装：

```shell
sudo dnf install $HOME/rpmbuild/RPMS/noarch/secharden-<版本>.noarch.rpm
```

### 使用

> secharden 的使用需要 root 权限，因此请确保以 root 用户或使用 `sudo` 执行命令。

secharden 提供了一个命令行工具，可以通过以下命令来应用安全加固规则：

```shell
secharden apply
```

**注意事项**：

1. 当使用 `secharden apply` 应用配置文件加固配置后，删除对应加固项并重新使用 `secharden apply` 并不能清除之前已生效的配置。
2. 安全加固操作记录在日志文件 `/var/log/secharden/secharden.log` 中。

> secharden 的使用说明详见 [命令行参数说明](secharden/README.md)。

#### 配置文件说明

**配置文件目录结构**

默认情况下，secharden 会在 `/etc/secharden` 目录中查找配置。该目录包含一个 `secharden.conf` 文件和一个 `secharden.conf.d`
目录。

`secharden.conf` 文件用于定义了全局配置和规则的启用状态。[secharden 安全防护能力配置](#secharden-安全防护能力配置)
一节描述的规则都可以在该文件中进行配置。用户可以通过编辑该文件来启用或禁用特定的安全加固规则。

建议用户在 `secharden.conf.d` 目录中创建子配置文件，该目录下的配置文件会按优先级覆盖 `secharden.conf`
的配置项。该目录下的配置文件必须满足以下要求：

- 配置文件命名格式为 `<优先级>-<名称>.conf`，例如 `01-disable_ptrace.conf`。其中，`<优先级>`
  是一个大于零的整数，表示配置文件的加载优先级，数字越小优先级越高。

**配置文件格式**

配置文件使用 yaml 格式，内包含一个以规则 ID 为键的字典，值为规则的配置参数。例如：

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

上述配置文件表示启用 `int.01`、`int.03` 和 `net.02` 规则，显式禁用了 `net.01` 规则，并为 `int.03` 规则指定了 selinux 标签。

除了各个规则定义的参数以外，在每个规则中，都有一个特殊的 `enabled` 参数，用于启用或禁用该规则，未显式指定 `enable`
参数的规则会默认开启。用户可以通过设置 `enabled: false` 来禁用某个规则，例如：

```yaml
int.01:
  enabled: false
```

**规则帮助信息**

用户可以通过 `secharden` 提供的帮助文档，获取对应的规则信息。

获取规则列表可以使用如下命令：

```shell
secharden list
```

用户还可以获取详细的规则描述，例如若要获取上述 `int.03` 规则可以使用如下命令查看规则信息：

```shell
secharden help int.03
```

### secharden 内置安全防护能力

secharden 工具提供了一系列的安全加固规则，这些规则可以通过配置文件进行管理和应用。每个规则都包含了特定的安全措施，用户可以根据需要启用或禁用这些规则。

详细的规则文档介绍参见：[安全 OS 配置工具](secharden/src/secharden/tools/README.md)。

#### 全栈完整性加固

在系统启动运行的任何阶段都面临篡改的风险，对系统、业务软件的篡改将导致系统运行的不可信。全栈完整性加固通过全周期的安全校验检测是否发生篡改攻击，目前支持以下几种完整性安全配置：

| ID     | 加固规则          | 保护范围 | 保护周期  |
|--------|---------------|------|-------|
| int.01 | 启用内核模块签名      | 内核模块 | 系统启动时 |
| int.02 | 启用 DIM 动态度量内核 | 内核代码 | 系统运行时 |
| int.03 | 启用 IMA 度量关键文件 | 用户文件 | 业务加载时 |

结合 [openEuler安全启动](https://docs.openeuler.openatom.cn/zh/docs/24.03_LTS_SP2/server/security/cert_signature/secure_boot.html)
，启动时校验加载的系统镜像的完整性，实现全周期的系统防篡改。

目前，int.01 与 int.02 已在 `secharden.conf` 配置文件中使用了下列字段开启：

```yaml
int.01:
int.02:
```

> 注意：int.02 规则依赖 dim 模块，用户需要使用以下命令安装 dim 模块：
> ```shell
> sudo yum install dim dim_tools
> ```

规则 int.03 可通过以下几个步骤完成本节全栈完整性加固操作：

1. IMA 标签设置

   secharden 通过 selinux 标签来区分需要 IMA 保护的用户文件范围。用户可通过以下指令为文件关联一个 selinux 标签：

   ```
   semanage fcontext -a -t $type $file
   restorecon -v $file
   ```

2. 规则使能

   创建配置文件 `/etc/secharden/secharden.conf.d/01-ima_tags.conf`，内容如下：

    ```yaml
    int.03:
      selinux_tags:
        - <你的 selinux 标签，例如 user_home_t>
    ```

int.03 配置完成后，使用 `secharden apply` 命令应用本节所有规则。

#### 内核加固

内核加固用于增强内核的安全性，防止攻击者通过内核漏洞进行攻击。目前支持以下几种安全配置：

| ID      | 加固规则          | 保护范围 |
|---------|---------------|------|
| kern.01 | 开启 BPF 加固功能   | 内核模块 |
| kern.02 | 启用内核 ASLR     | 内核代码 |
| kern.03 | 确保内核触发错误后直接退出 | 内核代码 |

目前，上述规则已在 `secharden.conf` 配置文件中使用了下列字段开启：

```yaml
kern.01:
kern.02:
kern.03:
```

用户无需额外配置，直接使用 `secharden apply` 命令应用本节所有规则。

#### 登录认证

登录认证用于保护系统登录认证过程，防止攻击者通过暴力破解等方式获取用户凭据。目前支持以下几种安全配置：

| ID       | 加固规则                       | 保护范围 |
|----------|----------------------------|------|
| login.01 | 禁止空口令登录                    | SSH  |
| login.02 | 禁止使用 PermitUserEnvironment | SSH  |
| login.03 | 禁用 root 用户通过 SSH 登录        | SSH  |
| login.04 | 禁用 SSH 的 TCP 转发功能          | SSH  |
| login.05 | 禁止使用 X11 Forwarding        | SSH  |
| login.06 | 禁止使用 SysRq 键               | 物理机  |
| login.07 | 避免开启 tcp_timestamps        | 网络   |
| login.08 | 设置最大认证次数                   | SSH  |

目前，上述规则已在 `secharden.conf` 配置文件中使用了下列字段开启：

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

用户无需额外配置，直接使用 `secharden apply` 命令应用本节所有规则。

#### 网络保护

网络保护用于保护系统的网络连接，防止攻击者通过网络进行攻击。目前支持以下几种安全配置：

| ID     | 加固规则              | 保护范围 |
|--------|-------------------|------|
| net.01 | 禁止 ICMP 重定向报文     | 网络   |
| net.02 | 禁止系统响应 ICMP 广播报文  | 网络   |
| net.03 | 禁止 IP 转发          | 网络   |
| net.04 | 禁止使用 ARP 代理       | 网络   |
| net.05 | 禁止报文源路由           | 网络   |
| net.06 | 丢弃伪造的 ICMP 报文     | 网络   |
| net.07 | 启用防火墙服务           | 网络   |
| net.08 | 启用反向地址过滤          | 网络   |
| net.09 | 启用 TCP-SYN cookie | 网络   |

目前，上述规则已在 `secharden.conf` 配置文件中使用了下列字段开启：

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

用户无需额外配置，直接使用 `secharden apply` 命令应用本节所有规则。

#### 权限最小化

权限最小化用于限制系统中用户和进程的权限，防止攻击者通过权限提升获取更高的权限。目前支持以下几种安全配置：

| ID      | 加固规则     | 保护范围 |
|---------|----------|------|
| priv.01 | 最小化文件权限  | 用户文件 |
| priv.02 | 启用链接文件保护 | 用户文件 |

目前，上述规则已在 `secharden.conf` 配置文件中使用了下列字段开启：

```yaml
priv.01:
priv.02:
```

用户无需额外配置，直接使用 `secharden apply` 命令应用本节所有规则。

### 启用安全服务

启用安全服务用于确保系统中安全服务的正常运行，防止攻击者通过关闭安全服务来降低系统的安全性。目前支持以下几种安全配置：

| ID      | 加固规则                  | 保护范围 |
|---------|-----------------------|------|
| serv.01 | 启用 rsyslog 服务         | 日志   |
| serv.02 | Selinux 启用 enforce 模式 | 用户文件 |

目前，上述规则已在 `secharden.conf` 配置文件中使用了下列字段开启：

```yaml
serv.01:
serv.02:
```

用户无需额外配置，直接使用 `secharden apply` 命令应用本节所有规则。

#### 限制高危系统功能

限制高危系统功能用于防止攻击者通过滥用系统功能来获取更高的权限或进行其他恶意操作。目前支持以下几种安全配置：

| ID     | 加固规则          | 保护范围 |
|--------|---------------|------|
| sys.01 | 配置 dmesg 访问权限 | 内核模块 |
| sys.02 | 禁止开启 kexec 功能 | 内核模块 |
| sys.03 | 限制内核符号读取权限    | 内核模块 |
| sys.04 | 限制 ptrace 范围  | 内核模块 |
| sys.05 | 禁用不常见网络服务     | 内核模块 |

目前，上述规则已在 `secharden.conf` 配置文件中使用了下列字段开启：

```yaml
sys.01:
sys.02:
sys.03:
sys.04:
sys.05:
```

用户无需额外配置，直接使用 `secharden apply` 命令应用本节所有规则。

## 最小安全系统配置指南

`docs` 目录包含了最小安全系统配置指南，主要包括以下内容：

- [配置指南](docs/README.md)
- [系统内核的配置文件](docs/openeuler_defconfig)
- [镜像构建使用的最小化裁剪配置文件](docs/normal.xml)

> 详细使用说明参见 [配置指南](docs/README.md)。
