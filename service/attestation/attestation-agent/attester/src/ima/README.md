# IMA (Integrity Measurement Architecture) Module

这个模块提供了读取和处理IMA日志的功能。

## 功能特性

- 读取系统IMA日志
- 检查IMA是否可用
- 条件性读取IMA日志（仅在请求时读取）
- 提供便捷的静态函数和面向对象的接口

## 使用方法

### 基本用法

```rust
use crate::ima::{ImaLogReader, read_ima_log, read_ima_log_if_requested};

// 使用面向对象的方式
let reader = ImaLogReader::new();
if reader.is_ima_available() {
    match reader.read_ima_log() {
        Ok(Some(log_data)) => {
            println!("IMA log read successfully: {} bytes", log_data.len());
        }
        Ok(None) => {
            println!("IMA log is empty or not available");
        }
        Err(e) => {
            eprintln!("Failed to read IMA log: {}", e);
        }
    }
}

// 使用便捷函数
match read_ima_log() {
    Ok(Some(log_data)) => {
        println!("IMA log read successfully: {} bytes", log_data.len());
    }
    Ok(None) => {
        println!("IMA log is empty or not available");
    }
    Err(e) => {
        eprintln!("Failed to read IMA log: {}", e);
    }
}

// 条件性读取
let with_ima = true; // 从用户请求中获取
match read_ima_log_if_requested(with_ima) {
    Ok(Some(log_data)) => {
        println!("IMA log read successfully: {} bytes", log_data.len());
    }
    Ok(None) => {
        println!("IMA log not requested or not available");
    }
    Err(e) => {
        eprintln!("Failed to read IMA log: {}", e);
    }
}
```

### 在TEE模块中使用

在virtcca或itrustee模块中，可以这样使用IMA模块：

```rust
use crate::ima;

// 在获取证据时读取IMA日志
let with_ima = match user_data.ima {
    Some(ima) => ima,
    None => false,
};

let ima_log = ima::read_ima_log_if_requested(with_ima)?;
```

## API 参考

### ImaLogReader

主要的IMA日志读取器类。

#### 方法

- `new() -> Self`: 创建新的IMA日志读取器实例
- `read_ima_log() -> Result<Option<Vec<u8>>>`: 读取IMA日志
- `is_ima_available() -> bool`: 检查IMA是否可用
- `read_ima_log_if_requested(with_ima: bool) -> Result<Option<Vec<u8>>>`: 条件性读取IMA日志

### 静态函数

- `read_ima_log() -> Result<Option<Vec<u8>>>`: 便捷函数，直接读取IMA日志
- `read_ima_log_if_requested(with_ima: bool) -> Result<Option<Vec<u8>>>`: 便捷函数，条件性读取IMA日志

## 错误处理

模块使用 `anyhow::Result` 进行错误处理。常见的错误包括：

- IMA日志文件不存在
- 文件读取权限不足
- 文件系统错误

## 注意事项

1. IMA日志路径固定为 `/sys/kernel/security/ima/binary_runtime_measurements`
2. 需要适当的文件系统权限才能读取IMA日志
3. 如果IMA未启用，读取操作会返回错误
4. 模块不会移动或修改CCEL相关的代码和接口 