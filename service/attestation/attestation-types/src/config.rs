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

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

pub const DEFAULT_AACONFIG_FILE: &str = "/etc/attestation/attestation-agent/attestation-agent.conf";

#[derive(Clone, Debug)]
pub struct TokenManager {
    // Token 相关信息
    current_token: Arc<RwLock<Option<String>>>,
    token_exp: Arc<RwLock<Option<u64>>>, // JWT 的 exp 字段（过期时间）
    consecutive_failures: Arc<AtomicU32>,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            current_token: Arc::new(RwLock::new(None)),
            token_exp: Arc::new(RwLock::new(None)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
        }
    }

    /// 解析 JWT 并提取过期时间
    fn parse_jwt_exp(&self, token: &str) -> Result<u64> {
        // 解析 JWT payload
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid JWT format"));
        }

        // 解码 payload (base64url)
        let payload = base64_url::decode(parts[1])?;
        let payload_str = String::from_utf8(payload)?;
        let claims: serde_json::Value = serde_json::from_str(&payload_str)?;

        // 提取 exp
        let exp = claims["exp"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing exp field"))?;

        Ok(exp)
    }

    // 存储 token
    pub async fn store_token(&self, token: String) -> Result<()> {
        let exp = self.parse_jwt_exp(&token)?;

        let mut token_guard = self.current_token.write().await;
        let mut exp_guard = self.token_exp.write().await;

        *token_guard = Some(token);
        *exp_guard = Some(exp);

        // 重置失败计数
        self.consecutive_failures.store(0, Ordering::Relaxed);
        Ok(())
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

    /// 检查 Token 是否过期（基于 exp 字段）
    pub async fn is_token_expired(&self) -> bool {
        let exp_guard = self.token_exp.read().await;
        if let Some(exp) = *exp_guard {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            current_time >= exp
        } else {
            true
        }
    }

    /// 获取 Token 的过期时间（exp）
    pub async fn get_token_expires_at(&self) -> Option<u64> {
        let exp_guard = self.token_exp.read().await;
        *exp_guard
    }

    /// 获取 Token 的剩余有效时间（秒）
    pub async fn get_token_ttl(&self) -> Option<i64> {
        let exp_guard = self.token_exp.read().await;
        if let Some(exp) = *exp_guard {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Some(exp as i64 - current_time as i64)
        } else {
            None
        }
    }

    /// 检查是否需要刷新 Token
    /// interval: 检查间隔（秒）
    pub async fn should_refresh_token(&self, interval: u64) -> bool {
        if let Some(ttl) = self.get_token_ttl().await {
            if ttl <= 0 {
                return true; // 已过期
            }

            // 策略1: 固定时间提前刷新（使用 interval）
            // 确保在下次检查前完成刷新
            let fixed_threshold = interval;

            // 策略2: 百分比提前刷新（剩余不足 10%）
            let percentage_threshold = (ttl as f64 * 0.1) as u64;

            // 取更保守的策略（更早刷新）
            let threshold = std::cmp::max(fixed_threshold, percentage_threshold);

            ttl <= threshold as i64
        } else {
            true // 没有 Token 时需要刷新
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
        let mut exp_guard = self.token_exp.write().await;

        *token_guard = None;
        *exp_guard = None;
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

#[derive(Clone, Debug, Deserialize)]
#[serde(from = "AppConfigDeserializable")]
pub struct AppConfig {
    pub uuid: String,
    // Preserves the UUID from the config file before runtime discovery mutates `uuid`.
    #[serde(skip)]
    configured_uuid: String,
    pub ima: bool,
    pub interval: u64,
    pub platform: crate::TeeType,
    #[serde(default)]
    pub rim_auto_discover: bool,
    #[serde(skip)]
    pub discovered_rim: Arc<std::sync::OnceLock<String>>,
    #[serde(skip)]
    pub token_manager: Arc<TokenManager>,
}

#[derive(Deserialize)]
struct AppConfigDeserializable {
    uuid: String,
    #[serde(default)]
    ima: bool,
    #[serde(default = "default_interval")]
    interval: u64,
    #[serde(default = "default_platform")]
    platform: crate::TeeType,
    #[serde(default)]
    rim_auto_discover: bool,
}

fn default_interval() -> u64 {
    30
}

fn default_platform() -> crate::TeeType {
    crate::TeeType::Invalid
}

impl AppConfig {
    pub fn new(
        uuid: String,
        ima: bool,
        interval: u64,
        platform: crate::TeeType,
        rim_auto_discover: bool,
    ) -> Self {
        let configured_uuid = uuid.clone();
        Self {
            uuid,
            configured_uuid,
            ima,
            interval,
            platform,
            rim_auto_discover,
            discovered_rim: Arc::new(std::sync::OnceLock::new()),
            token_manager: Arc::new(TokenManager::new()),
        }
    }

    // 便捷方法：委托给 TokenManager
    pub async fn store_token(&self, token: String) -> Result<()> {
        self.token_manager.store_token(token).await
    }

    pub async fn get_token(&self) -> Option<String> {
        self.token_manager.get_token().await
    }

    pub async fn has_token(&self) -> bool {
        self.token_manager.has_token().await
    }

    // 检查Token是否过期
    pub async fn is_token_expired(&self) -> bool {
        self.token_manager.is_token_expired().await
    }

    // 检查是否需要刷新 Token
    pub async fn should_refresh_token(&self) -> bool {
        self.token_manager.should_refresh_token(self.interval).await
    }

    // 获取 Token 过期时间
    pub async fn get_token_expires_at(&self) -> Option<u64> {
        self.token_manager.get_token_expires_at().await
    }

    // 获取 Token 剩余有效时间
    pub async fn get_token_ttl(&self) -> Option<i64> {
        self.token_manager.get_token_ttl().await
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

    pub fn configured_uuid(&self) -> &str {
        &self.configured_uuid
    }
}

impl Serialize for AppConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AppConfig", 5)?;
        state.serialize_field("uuid", &self.configured_uuid)?;
        state.serialize_field("ima", &self.ima)?;
        state.serialize_field("interval", &self.interval)?;
        state.serialize_field("platform", &self.platform)?;
        state.serialize_field("rim_auto_discover", &self.rim_auto_discover)?;
        state.end()
    }
}

impl From<AppConfigDeserializable> for AppConfig {
    fn from(deserializable: AppConfigDeserializable) -> Self {
        AppConfig::new(
            deserializable.uuid,
            deserializable.ima,
            deserializable.interval,
            deserializable.platform,
            deserializable.rim_auto_discover,
        )
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
    // {
    //     "svr_url": "http://127.0.0.1:8080",
    //     "token_cfg": {
    //         "cert": "/etc/attestation/attestation-agent/as_cert.pem",
    //         "iss": "oeas"
    //     },
    //     "protocal": {
    //         "Http": {
    //             "protocal": "http"
    //         }
    //     },
    //     "enable_active_attestation": true,
    //     "app_list": [
    //         {
    //             "uuid": "f68fd704-6eb1-4d14-b218-722850eb3ef0",
    //             "ima": true,
    //             "interval": 30,
    //             "platform": "itrustee"
    //         },
    //         {
    //             "uuid": "0715F5BA-13A2-478B-BD60-B43B645E23DE", // RIM of VM
    //             "ima": false,
    //             "interval": 60,
    //             "platform": "virtcca"
    //         }
    //     ]
    // }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path).unwrap();
        let mut config: AAConfig = serde_json::from_reader::<File, AAConfig>(file)
            .map_err(|e| anyhow::anyhow!("invalid aaconfig {e}"))?;

        // 为每个应用初始化 TokenManager
        config.app_list = config
            .app_list
            .into_iter()
            .map(|app| {
                AppConfig::new(
                    app.uuid,
                    app.ima,
                    app.interval,
                    app.platform,
                    app.rim_auto_discover,
                )
            })
            .collect();

        Ok(config)
    }
}

impl AAConfig {
    pub fn get_token_cfg(&self) -> &TokenVerifyConfig {
        &self.token_cfg
    }
}
