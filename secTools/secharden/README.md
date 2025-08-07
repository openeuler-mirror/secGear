# secharden

## 简介

secharden 是一个基于 python 的系统加固框架，用于管理和应用各种安全加固规则。
它提供了一个灵活的方式来增强系统的安全性，支持多种加固规则的配置和执行。

## 安装

使用 pip 安装 secharden：

```bash
python3 -m pip install .
```

## 使用

secharden 命令提供了多种功能，包括应用加固规则、打印加固规则列表、查看规则的帮助信息等。

### 应用加固规则

secharden 会读取配置文件并应用对应的加固规则。

如果用户没有指定规则路径，则会使用默认的 `/etc/secharden` 目录：

```bash
secharden apply
```

如果用户需要指定规则路径可以在 `secharden apply` 后指定：

```bash
secharden apply [/path/to/config_path]
```

secharden 会输出应用的规则，示例如下：

```plaintext
Applying rule: int.01...
```

#### 配置文件目录

**配置文件目录结构**

指定的规则路径必须是一个目录。且该目录中必须包含一个基础配置文件 `secharden.conf`。

用户还可以创建一个 `secharden.conf.d` 目录，在该目录下放置多个配置文件，工具会自动加载这些配置文件。该目录下的配置文件必须满足以下要求：

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

在每个规则中，都有一个特殊的 `enabled` 参数，用于启用或禁用该规则。默认情况下，所有规则都被启用。用户可以通过设置
`enabled: false` 来禁用某个规则，例如：

```yaml
int.01:
  enabled: false
```

### 打印加固规则列表

用户可以使用 `secharden list` 命令打印当前加载的加固规则列表。该命令会列出所有可用的规则。用户也可以传入参数来查看指定类别的规则列表。

```bash
secharden list [类别 ID]
```

结果示例如下：

```plaintext
int: 全栈完整性
        int.01: 启用内核模块签名
        int.02: 启用DIM动态度量内核
        int.03: 启用IMA度量关键文件
kern: 内核加固
        kern.01: 开启BPF加固功能
        kern.02: 启用内核ASLR
        kern.03: 确保内核触发错误后直接退出
```

### 查看规则的帮助信息

传入参数可以查看指定类别或规则的帮助信息，用户可以传入规则 ID 或者类别 ID 查看相应的帮助信息。

```bash
secharden help <规则 ID 或 类别 ID>
```

结果示例如下：

```plaintext
### int.01 启用内核模块签名

启用内核模块签名。内核模块签名以一定格式在内核模块文件末尾添加签名信息，系统在加载内核模块时检查签名是否与内核中预设的公钥匹配。这样可以验证内核模块文件的真实性和完整性，防止系统加载未经认证的恶意内核模块。

#### 参数

无

```

### 通用命令参数

以下命令参数适用于所有 secharden 命令。这些命令必须在 `secharden` 命令后使用。例如：

```bash
secharden --rules /path/to/rules apply /path/to/config_path
```

#### 版本信息

打印当前 secharden 的版本信息：

```bash
secharden --version
```

#### 指定规则路径

如果需要指定规则路径，可以使用 `--rules` 或 `-r` 参数指定。默认值为工具目录中的 `tools` 目录：

```bash
secharden --rules /path/to/rules
```

> 注意：指定的规则路径必须是一个目录。且该目录中必须包含 `categories.json` 描述规则类别，各个规则目录需满足以下要求：
> - 每个规则目录必须包含一个 `metadata.json` 文件，描述该规则的详细信息。
> - 规则目录的名称必须为 <类别>.<序号>，例如 `system.01`、`network.02` 等。且类别必须与 `categories.json` 中的类别一致。
> - 规则目录下的 `metadata.json` 文件必须满足工具目录中的 `schema/metadata.json` 规范。

工具会校验当前规则路径下的规则路径，若目录不符合要求，则不会加载到工具规则列表中。
如果用户使用自定义的规则路径，建议使用以下命令来查看规则路径是否被加载到列表中：

```bash
secharden -r /path/to/rules list
```

若不满足要求，查询工具 log 文件中的错误信息。

#### 指定 log 路径

如果需要指定 log 路径，可以使用 `--log` 或 `-l` 参数指定。默认值为 `/var/log/secharden`：

```bash
secharden --log /path/to/log_directory
```

> 注意：指定的 log 路径必须是一个目录。

#### 开启 debug 模式

如果需要开启 debug 模式，可以使用 `--debug` 或 `-d` 参数：

```bash
secharden --debug
```

开启后，工具会在 log 文件中输出更多的调试信息，帮助用户排查问题。
