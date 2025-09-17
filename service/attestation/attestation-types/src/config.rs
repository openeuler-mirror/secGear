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

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::fs::File;
use anyhow::Result;

pub const DEFAULT_AACONFIG_FILE: &str = "/etc/attestation/attestation-agent/attestation-agent.conf";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HttpProtocal {
    Http { protocal: String },
    // If https is uesd, the root certificate must be provided.
    Https { protocal: String, cert_root: String },
}

impl Default for HttpProtocal {
    fn default() -> Self {
        Self::Http {
            protocal: "http".to_string(),
        }
    }
}

impl HttpProtocal {
    pub fn get_protocal(&self) -> String {
        match self {
            Self::Http { protocal } => protocal,
            Self::Https { protocal, .. } => protocal,
        }
        .clone()
    }

    pub fn get_cert_root(&self) -> Option<String> {
        match self {
            Self::Https { cert_root, .. } => Some(cert_root.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenVerifyConfig {
    pub cert: String, // Attestation Service cert to verify jwt token signature
    pub iss: String,  // Attestation Service name
}

impl Default for TokenVerifyConfig {
    fn default() -> Self {
        TokenVerifyConfig {
            cert: "/etc/attestation/attestation-agent/as_cert.pem".to_string(),
            iss: "oeas".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub uuid: String,
    pub ima: bool,
    pub interval: u64,
    pub platform: crate::TeeType,
}

impl Serialize for AppConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AppConfig", 4)?;
        state.serialize_field("uuid", &self.uuid)?;
        state.serialize_field("ima", &self.ima)?;
        state.serialize_field("interval", &self.interval)?;
        state.serialize_field("platform", &self.platform)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AppConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct AppConfigVisitor;

        impl<'de> Visitor<'de> for AppConfigVisitor {
            type Value = AppConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct AppConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<AppConfig, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut uuid = None;
                let mut ima = None;
                let mut interval = None;
                let mut platform = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "uuid" => {
                            if uuid.is_some() {
                                return Err(de::Error::duplicate_field("uuid"));
                            }
                            uuid = Some(map.next_value()?);
                        }
                        "ima" => {
                            if ima.is_some() {
                                return Err(de::Error::duplicate_field("ima"));
                            }
                            ima = Some(map.next_value()?);
                        }
                        "interval" => {
                            if interval.is_some() {
                                return Err(de::Error::duplicate_field("interval"));
                            }
                            interval = Some(map.next_value()?);
                        }
                        "platform" => {
                            if platform.is_some() {
                                return Err(de::Error::duplicate_field("platform"));
                            }
                            platform = Some(map.next_value()?);
                        }
                        _ => {
                            let _ = map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }

                let uuid = uuid.ok_or_else(|| de::Error::missing_field("uuid"))?;
                let ima = ima.unwrap_or(false); // 默认值为 false
                let interval = interval.unwrap_or(30); // 默认值为 30
                let platform = platform.unwrap_or(crate::TeeType::Invalid); // 默认值为 Invalid

                Ok(AppConfig {
                    uuid,
                    ima,
                    interval,
                    platform,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["uuid", "ima", "interval", "platform"];
        deserializer.deserialize_struct("AppConfig", FIELDS, AppConfigVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AAConfig {
    // Attestation Service url
    pub svr_url: String,
    // Http protocal, such as http or https
    pub protocal: HttpProtocal,
    token_cfg: TokenVerifyConfig,
    // active attestation switch
    pub enable_active_attestation: bool,
    // list of apps for active attestation
    pub app_list: Vec<AppConfig>,
}

impl Default for AAConfig {
    fn default() -> Self {
        Self {
            svr_url: String::from("http://127.0.0.1:8080"),
            token_cfg: TokenVerifyConfig::default(),
            protocal: HttpProtocal::default(),
            enable_active_attestation: false,
            app_list: Vec::new(),
        }
    }
}

impl TryFrom<&Path> for AAConfig {
    /// Load `AAConfig` from a configuration file like:
    ///    {
    ///        "svr_url": "http://127.0.0.1:8080",
    ///        "token_cfg": {
    ///            "cert": "/etc/attestation/attestation-agent/as_cert.pem",
    ///            "iss": "oeas"
    ///        }
    ///    }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path).unwrap();
        serde_json::from_reader::<File, AAConfig>(file).map_err(|e| anyhow::anyhow!("invalid aaconfig {e}"))
    }
}

impl AAConfig {
    pub fn get_token_cfg(&self) -> &TokenVerifyConfig {
        &self.token_cfg
    }
}
