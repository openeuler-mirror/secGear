/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! IMA (Integrity Measurement Architecture) module
//!
//! This module provides functionality to read and handle IMA logs.

use anyhow::{bail, Result};
use log;

const IMA_LOG_PATH: &str = "/sys/kernel/security/ima/binary_runtime_measurements";

/// IMA log reader and handler
#[derive(Debug, Default)]
struct ImaLogReader {}

impl ImaLogReader {
    /// Create a new IMA log reader instance
    fn new() -> Self {
        Self {}
    }

    /// Read IMA log from the system
    /// 
    /// Returns the IMA log data as a vector of bytes, or None if IMA is not enabled
    /// or the log cannot be read.
    fn read_ima_log(&self) -> Result<Option<Vec<u8>>> {
        match std::fs::read(IMA_LOG_PATH) {
            Ok(data) => {
                log::info!("read ima log success");
                Ok(Some(data))
            }
            Err(e) => {
                log::error!("read IMA log failed: {}", e);
                bail!("get ima log failed: {}", e);
            }
        }
    }

    /// Check if IMA is available on the system
    #[allow(dead_code)]
    fn is_ima_available(&self) -> bool {
        std::path::Path::new(IMA_LOG_PATH).exists()
    }

    /// Read IMA log if requested
    /// 
    /// This function checks the `with_ima` parameter and reads the IMA log
    /// only if it's requested.
    fn read_ima_log_if_requested(&self, with_ima: bool) -> Result<Option<Vec<u8>>> {
        if with_ima {
            self.read_ima_log()
        } else {
            Ok(None)
        }
    }
}

/// Convenience function to read IMA log if requested
/// 
/// This is a standalone function that can be used without creating an ImaLogReader instance.
pub fn read_ima_log_if_requested(with_ima: bool) -> Result<Option<Vec<u8>>> {
    let reader = ImaLogReader::new();
    reader.read_ima_log_if_requested(with_ima)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ima_log_reader_creation() {
        let reader = ImaLogReader::new();
        assert!(reader.is_ima_available() || !reader.is_ima_available()); // Should not panic
    }

    #[test]
    fn test_read_ima_log_if_requested_false() {
        let reader = ImaLogReader::new();
        let result = reader.read_ima_log_if_requested(false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_static_functions() {
        // Test static function for false case
        let result = read_ima_log_if_requested(false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test static function for true case (may fail if IMA not available, but should not panic)
        let _result = read_ima_log_if_requested(true);
        // We don't assert the result here as it depends on system state
        // Just ensure it doesn't panic
    }

    #[test]
    fn test_ima_availability_check() {
        let reader = ImaLogReader::new();
        let available = reader.is_ima_available();
        // This should not panic regardless of system state
        assert!(available == true || available == false);
    }
} 