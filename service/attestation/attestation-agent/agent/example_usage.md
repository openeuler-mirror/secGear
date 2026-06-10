# Platform 枚举字符串转换使用示例

## 概述

本文档展示了如何将字符串（如 "itrustee"、"VirtCCA"）映射到相应的 `Platform` 枚举类型。

## 实现的功能

1. **字符串到枚举转换** (`FromStr` trait)
2. **枚举到字符串转换** (`Display` trait)
3. **JSON 序列化/反序列化** (`Serialize`/`Deserialize` traits)

## 支持的字符串格式

- `"itrustee"` → `Platform::Itrustee`
- `"virtcca"` → `Platform::Virtcca`
- `"cca"` → `Platform::CCA`
- 其他任何字符串 → `Platform::Unknown`

**注意**: 转换不区分大小写，所以 `"Itrustee"`、`"ITRUSTEE"`、`"VirtCCA"` 等都能正确转换。

## 使用示例

### 1. 字符串到枚举转换

```rust
use std::str::FromStr;
use attestation_agent::Platform;

// 基本用法
let platform = Platform::from_str("itrustee").unwrap();
assert_eq!(platform, Platform::Itrustee);

// 不区分大小写
let platform = Platform::from_str("VirtCCA").unwrap();
assert_eq!(platform, Platform::Virtcca);

// 未知字符串
let platform = Platform::from_str("unknown_platform").unwrap();
assert_eq!(platform, Platform::Unknown);
```

### 2. 枚举到字符串转换

```rust
use attestation_agent::Platform;

let platform = Platform::Itrustee;
assert_eq!(platform.to_string(), "itrustee");

let platform = Platform::Virtcca;
assert_eq!(platform.to_string(), "virtcca");
```

### 3. JSON 序列化/反序列化

```rust
use serde_json;
use attestation_agent::{Platform, AppConfig};

// 序列化
let platform = Platform::Itrustee;
let json = serde_json::to_string(&platform).unwrap();
assert_eq!(json, "\"itrustee\"");

// 反序列化
let platform: Platform = serde_json::from_str("\"virtcca\"").unwrap();
assert_eq!(platform, Platform::Virtcca);

// AppConfig 反序列化（支持配置文件格式）
let json = r#"{
    "uuid": "f68fd704-6eb1-4d14-b218-722850eb3ef0",
    "ima": true,
    "interval": 30,
    "platform": "itrustee"
}"#;

let app_config: AppConfig = serde_json::from_str(json).unwrap();
assert_eq!(app_config.platform, Platform::Itrustee);
```

### 4. 配置文件示例

现在配置文件中的 `platform` 字段可以直接使用字符串：

```json
{
    "svr_url": "http://127.0.0.1:8080",
    "enable_active_attestation": true,
    "app_list": [
        {
            "uuid": "f68fd704-6eb1-4d14-b218-722850eb3ef0",
            "ima": true,
            "interval": 30,
            "platform": "itrustee"
        },
        {
            "uuid": "0715F5BA-13A2-478B-BD60-B43B645E23DE",
            "ima": false,
            "interval": 60,
            "platform": "virtcca"
        }
    ]
}
```

## 错误处理

- 如果字符串无法识别，会返回 `Platform::Unknown` 而不是错误
- JSON 反序列化时，如果 `platform` 字段缺失，会使用 `Platform::Unknown` 作为默认值

## 测试

运行以下命令来测试所有功能：

```bash
cargo test platform
cargo test appconfig
```