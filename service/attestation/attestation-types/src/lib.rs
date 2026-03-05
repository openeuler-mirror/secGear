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

pub mod resource;
pub mod service;
pub mod config;
pub mod error;

#[cfg(test)]
mod tests;

// 重新导出常用类型
pub use config::{AppConfig, AAConfig, HttpProtocal, TokenVerifyConfig, DEFAULT_AACONFIG_FILE};
pub use error::AgentError;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

pub const SESSION_TIMEOUT_MIN: i64 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct UefiLog {
    pub ccel_table: Vec<u8>,
    pub ccel_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtccaEvidence {
    pub evidence: Vec<u8>,
    pub dev_cert: Vec<u8>,
    pub ima_log: Option<Vec<u8>>,
    pub uefi_log: Option<UefiLog>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TeeType {
    Itrustee = 1,
    Virtcca,
    Rustcca,
    Invalid,
}

impl std::str::FromStr for TeeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "itrustee" => Ok(TeeType::Itrustee),
            "virtcca" => Ok(TeeType::Virtcca),
            "rustcca" => Ok(TeeType::Rustcca),
            "cca" => Ok(TeeType::Rustcca), // 将 CCA 映射到 Rustcca
            _ => Ok(TeeType::Invalid),
        }
    }
}

impl std::fmt::Display for TeeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeType::Itrustee => write!(f, "itrustee"),
            TeeType::Virtcca => write!(f, "virtcca"),
            TeeType::Rustcca => write!(f, "rustcca"),
            TeeType::Invalid => write!(f, "invalid"),
        }
    }
}

impl Serialize for TeeType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TeeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // 首先尝试作为字符串反序列化
        struct TeeTypeVisitor;
        
        impl<'de> serde::de::Visitor<'de> for TeeTypeVisitor {
            type Value = TeeType;
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing a TEE type")
            }
            
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                TeeType::from_str(v).map_err(serde::de::Error::custom)
            }
            
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                TeeType::from_str(&v).map_err(serde::de::Error::custom)
            }
        }
        
        deserializer.deserialize_str(TeeTypeVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ItrusteeEvidence {
    pub report: String,
    pub ima_log: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub tee: TeeType,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvlResult {
    pub eval_result: bool,
    pub policy: Vec<String>,
    pub report: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub evaluation_reports: EvlResult,
    pub tee: String,
    pub tcb_status: Value,
}
