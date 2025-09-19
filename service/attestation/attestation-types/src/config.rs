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
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::RwLock;
use std::time::Instant;
use std::time::Duration;

pub const DEFAULT_AACONFIG_FILE: &str = "/etc/attestation/attestation-agent/attestation-agent.conf";

#[derive(Clone, Debug)]
pub struct TokenManager {
    // Token 相关信息
    current_token: Arc<RwLock<Option<String>>>,
    token_created_at: Arc<RwLock<Option<Instant>>>,
    consecutive_failures: Arc<AtomicU32>,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            current_token: Arc::new(RwLock::new(None)),
            token_created_at: Arc::new(RwLock::new(None)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
        }
    }

    // 存储 token
    pub async fn store_token(&self, token: String) {
        let mut token_guard = self.current_token.write().await;
        let mut time_guard = self.token_created_at.write().await;
        
        *token_guard = Some(token);
        *time_guard = Some(Instant::now());
        
        // 重置失败计数
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    // 获取 token
    pub async fn get_token(&self) -> Option<String> {
        let token_guard = self.current_token.read().await;
        token_guard.clone()
    }

    // 检查是否有 token
    pub async fn has_token(&self) -> bool {
        let token_guard = self.current_token.read().await;
        token_guard.is_some()
    }

    // 检查 token 是否过期
    pub async fn is_token_expired(&self, max_age_seconds: u64) -> bool {
        let time_guard = self.token_created_at.read().await;
        if let Some(created_at) = *time_guard {
            Instant::now() - created_at > Duration::from_secs(max_age_seconds)
        } else {
            true
        }
    }

    // 记录失败
    pub fn record_failure(&self) {
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
    }

    // 获取失败次数
    pub fn get_failure_count(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    // 重置失败计数
    pub fn reset_failures(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    // 清理 token
    pub async fn clear_token(&self) {
        let mut token_guard = self.current_token.write().await;
        let mut time_guard = self.token_created_at.write().await;
        
        *token_guard = None;
        *time_guard = None;
    }

    // 获取 token 存储时间
    pub async fn get_created_at(&self) -> Option<Instant> {
        let time_guard = self.token_created_at.read().await;
        *time_guard
    }
}


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
    // 使用独立的 TokenManager
    pub token_manager: Arc<TokenManager>,
}

impl AppConfig {
    pub fn new(uuid: String, ima: bool, interval: u64, platform: crate::TeeType) -> Self {
        Self {
            uuid,
            ima,
            interval,
            platform,
            token_manager: Arc::new(TokenManager::new()),
        }
    }

    // 便捷方法：委托给 TokenManager
    pub async fn store_token(&self, token: String) {
        self.token_manager.store_token(token).await;
    }

    pub async fn get_token(&self) -> Option<String> {
        self.token_manager.get_token().await
    }

    pub async fn has_token(&self) -> bool {
        self.token_manager.has_token().await
    }

    pub async fn is_token_expired(&self, max_age_seconds: u64) -> bool {
        self.token_manager.is_token_expired(max_age_seconds).await
    }

    pub fn record_failure(&self) {
        self.token_manager.record_failure();
    }

    pub fn get_failure_count(&self) -> u32 {
        self.token_manager.get_failure_count()
    }

    pub fn reset_failures(&self) {
        self.token_manager.reset_failures();
    }

    // 新增：获取 token 存储时间
    pub async fn get_token_created_at(&self) -> Option<Instant> {
        self.token_manager.get_created_at().await
    }
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

                Ok(AppConfig::new(uuid, ima, interval, platform))
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
        let mut config: AAConfig = serde_json::from_reader::<File, AAConfig>(file).map_err(|e| anyhow::anyhow!("invalid aaconfig {e}"))?;
        
        // 为每个应用初始化 TokenManager
        config.app_list = config.app_list.into_iter().map(|app| {
            AppConfig::new(app.uuid, app.ima, app.interval, app.platform)
        }).collect();
        
        Ok(config)
    }
}

impl AAConfig {
    pub fn get_token_cfg(&self) -> &TokenVerifyConfig {
        &self.token_cfg
    }
}
