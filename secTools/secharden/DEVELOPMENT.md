# secharden 开发文档

本项目使用 uv 进行开发和管理。要开始开发，请确保安装了 uv：

```bash
python3 -m pip install uv
```

安装 uv 后，可以使用以下命令同步开发依赖：

```bash
uv sync
```

## 项目架构

项目的目录结构如下：

```
secharden：主目录
├── src：源码目录
│   ├── secharden：secharden 包目录
│   │   ├── devtools：开发工具目录
│   │   │   └── gendoc.py：规则文档生成工具
│   │   ├── rule_metadata：规则元数据解析
│   │   │   ├── converters：配置转换器目录，用于将配置项转换为规则元数据定义的参数
│   │   │   │   ├── __init__.py
│   │   │   │   └── file_list.py：将配置数组写入临时文件，并将文件路径作为参数传递给规则元数据定义的参数
│   │   │   ├── __init__.py
│   │   │   ├── manager.py：规则元数据管理器，用于加载和解析规则元数据
│   │   │   ├── metadata.py：规则元数据定义类，负责解析 metadata.json 文件
│   │   ├── schema/
│   │   │   ├── categories.schema.json：规则分类的 JSON Schema 定义
│   │   │   └── metadata.schema.json：规则元数据的 JSON Schema 定义
│   │   ├── tools/
│   │   │   ├── categories.json：规则分类定义文件
│   │   │   ├── README.md：规则分类说明文档
│   │   │   ├── <类别>.<序号>：规则目录
│   │   │   │   ├── metadata.json：规则元数据定义文件
│   │   │   │   └── ...
│   │   │   └── ...
│   │   ├── __init__.py
│   │   ├── config_parser.py：配置解析器，用于解析 secharden 配置文件
│   │   ├── executor.py：执行器，用于执行运行规则
│   │   ├── secharden.py：secharden 包的入口文件，包含主逻辑
│   │   ├── utils.py：工具函数集合
├── tests：测试目录
├── DEVELOPMENT.md：开发文档
├── MANIFEST.in：清单文件，指定哪些文件需要包含在分发包中
├── pyproject.toml：项目配置文件，包含依赖和构建信息
├── README.md：项目说明文档
└── uv.lock：uv 锁定文件，记录依赖版本信息
```

## 新建规则集

新建规则集时，需要新建一个目录，并在该目录下创建 `categories.json` 文件，该文件用于定义规则分类。以下是一个示例
`categories.json` 文件：

```json
{
  "int": {
    "name": "全栈完整性",
    "description": "全栈完整性加固用于业务软件全生命周期不被篡改。"
  }
}
```

该规则集中，每一个键代表规则分类的唯一标识符，格式为 `<类别>`，例如 `int`。每个值需包含以下字段：

- `name`：规则分类名称。
- `description`：规则分类描述。

### 新建规则

在新建的规则集目录中，创建一个规则目录，命名格式为 `<类别>.<序号>`，例如 `int.01`。
在该目录下创建 `metadata.json` 文件，该文件用于定义规则元数据。以下是一个示例 `metadata.json` 文件：

```json
{
  "id": "int.01",
  "name": "启用IMA度量关键文件",
  "description": "启用IMA度量关键文件。IMA 度量是一个开源的可信计算组件。其维护了一个运行时度量列表，并在 TPM 设备存在时则针对该列表生成整体完整性度量值并记录到 TPM 中。",
  "entry": "enforce_ima.sh",
  "parameters": [
    {
      "id": "selinux_tags",
      "name": "selinux 标签列表文件",
      "description": "该文件包含一个 selinux 标签列表，表示这些标签需要被 ima 度量。要求文件每行一个标签。",
      "converter": "FileListConverter",
      "cmd_template": "%file"
    }
  ],
  "urls": [
    {
      "title": "Integrity Measurement Architecture (IMA) Wiki",
      "url": "https://sourceforge.net/p/linux-ima/wiki/Home/"
    }
  ]
}
```

该规则元数据包含以下字段：

- `id`：规则的唯一标识符，格式为 `<类别>.<序号>`，例如 `int.01`。
- `name`：规则名称。
- `description`：规则描述。
- `entry`：规则的入口脚本文件名，也可以是一个可执行文件名。secharden 会搜索当前目录下的文件以及环境变量 `PATH` 中的可执行文件。
- `parameters`（可选）：规则参数列表。每个参数包含以下字段：
    - `id`：参数的唯一标识符。
    - `name`：参数名称。
    - `description`：参数描述。
    - `converter`：参数转换器类名，用于将配置项转换为规则元数据定义的参数。
    - `cmd_template`：命令行模板，用于生成执行命令。该模板可以包含参数占位符，例如 `%file`。参数占位符需要配合 `converter`
      使用。
- `urls`（可选）：相关链接列表。每个链接包含以下字段：
    - `title`：链接标题。
    - `url`：链接地址。

开发者还可以根据自身需求添加其他文件。

### 转换器开发

转换器用于将配置项转换为规则元数据定义的参数。转换器需要继承 `secharden.rule_metadata.metadata.Converter` 类，
并实现 `verify` 和 `generate` 方法，开发者还可以实现 `cleanup` 方法以完成生成后清理功能。

#### 转换器 `verify` 方法

`verify` 方法用于验证配置项是否符合规则元数据定义的参数要求，方法函数签名如下：

```python
from secharden.rule_metadata import RuleParameter


def verify(self, parameter: RuleParameter):
    pass
```

- `parameter`: `RuleParameter` 是一个包含规则参数信息的对象，开发者可以上述规则列表中 `parameters` 字段信息。

开发者应验证配置项是否符合规则元数据定义的参数要求，尤其是上述的 `cmd_template` 字段是否满足要求。如果验证不通过，需要抛出异常以提示框架。

#### 转换器 `generate` 方法

`generate` 方法用于将配置项转换为规则元数据定义的参数，方法函数签名如下：

```python
from secharden.executor import CmdParameter


def generate(self, parameter: CmdParameter, config):
    pass
```

- `parameter`: `CmdParameter` 是一个包含命令行参数信息的对象。该类除了包含 `RuleParameter` 的所有字段外， 还包含了
  `add_variable` 和 `add_env` 函数。
    - `add_variable(name, value)`：添加一个占位符键值对。框架根据 `cmd_template` 中的占位符生成命令行参数时会查询并替换为相应的
      `value`。
    - `add_env(name, value)`：添加一个环境变量。框架最终运行规则时会将该环境变量添加到执行环境中。
- `config`: `config` 参数是由配置文件解析器解析后的配置项。开发者可以根据规则元数据定义的参数要求，从 `config` 中提取相应的值，并使用
  `CmdParameter`提供的上述函数添加到命令行参数中。

#### 转换器 `cleanup` 方法

`cleanup` 方法是一个可选方法，用于在规则执行后进行清理工作。方法函数签名如下：

```python
def cleanup(self):
    pass
```

`cleanup` 方法可以用于删除临时文件或其他清理工作。该方法在规则执行完成后被调用，开发者可以根据需要实现该方法。

> 注意：`cleanup` 方法仅会在 `generate` 方法成功执行后被调用。如果 `generate` 方法抛出异常，`cleanup` 方法将不会被调用。

## 规则文档生成工具

`devtools` 提供了 `gendoc` 命令来生成规则文档。该文档通过解析 `categories.json` 和 `metadata.json` 文件生成 `README.md`
文档。
可以使用以下命令生成文档：

```shell
uv run src/secharden/devtools/gendoc.py
```

### 选项

- `--rules` 或 `-r`：指定规则路径，默认值为 `tools` 目录。文档会生成到该目录下。
- `--force` 或 `-f`：强制覆盖已存在的文档。若不指定该选项，工具会检查文档是否已存在，若存在则会报错退出。
- `--version` 或 `-v`：打印当前工具版本信息。
- `--debug` 或 `-d`：开启调试模式，输出更多的调试信息。

## 单元测试

本项目使用 pytest 进行单元测试。相关依赖已通过 `uv sync` 安装。

要运行单元测试，请使用以下命令：

```bash
uv run pytest
```

> pytest 相关使用说明参见 [pytest 官方文档](https://docs.pytest.org/en/stable/contents.html)。
