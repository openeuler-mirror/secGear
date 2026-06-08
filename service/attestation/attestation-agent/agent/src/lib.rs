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
#![allow(clippy::redundant_field_names)]
#![allow(clippy::needless_return)]

//! Attestation Agent
//!
//! This crate provides some APIs to get and verify the TEE evidence.
//! Current supports kunpeng itrustee and virtcca TEE types.

pub mod restapi;
pub mod result;

use actix_web::web::Bytes;
use anyhow::{bail, Result};
use async_trait::async_trait;
use attestation_types::{
    resource::ResourceLocation, service::GetResourceOp, AAConfig, AgentError, AppConfig,
    HttpProtocal, TeeType, DEFAULT_AACONFIG_FILE,
};
use attester::{Attester, AttesterAPIs};
#[cfg(feature = "virtcca-attester")]
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::Serialize;

use rand::{Rng, RngCore};
use reqwest::Client;
use result::Error;
use serde_json::json;
use serde_json::Value;
use std::path::Path;
use std::{error::Error as StdError, fmt};
use token_verifier::{TokenRawData, TokenVerifier};

pub type TeeClaim = serde_json::Value;

#[cfg(feature = "no_as")]
use verifier::{Verifier, VerifierAPIs};

#[cfg(not(feature = "no_as"))]
use reqwest::header::{HeaderMap, HeaderValue};

pub use attester::EvidenceRequest;
mod session;
use attestation_types::SESSION_TIMEOUT_MIN;
use session::{Session, SessionMap};
pub type AsTokenClaim = TokenRawData;

pub struct TokenRequest {
    pub ev_req: EvidenceRequest,
    pub policy_id: Option<Vec<String>>,
}

#[derive(Serialize, Debug)]
pub struct ActiveTokenResponse {
    pub jwt_token: Option<String>,
    pub expires_at: Option<u64>,
    pub ttl_seconds: Option<i64>,
    pub cvm_token: Option<String>,
    pub dev_cert: Option<String>,
    pub error: Option<String>,
    pub failure_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveTokenError {
    InvalidUuid,
    MissingNonce,
    PlatformMismatch,
    AppNotFound,
    AmbiguousApp,
    NotSupported,
    NoTokenAvailable,
    TeeUnavailable,
}

impl fmt::Display for ActiveTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid => write!(f, "invalid_uuid"),
            Self::MissingNonce => write!(f, "missing_nonce"),
            Self::PlatformMismatch => write!(f, "platform_mismatch"),
            Self::AppNotFound => write!(f, "app_not_found"),
            Self::AmbiguousApp => write!(f, "ambiguous_app"),
            Self::NotSupported => write!(f, "not_supported"),
            Self::NoTokenAvailable => write!(f, "no_token_available"),
            Self::TeeUnavailable => write!(f, "tee_unavailable"),
        }
    }
}

impl StdError for ActiveTokenError {}

fn detect_active_token_runtime_platform() -> TeeType {
    #[cfg(feature = "itrustee-attester")]
    if attester::itrustee::detect_platform() {
        return TeeType::Itrustee;
    }

    #[cfg(feature = "virtcca-attester")]
    if attester::virtcca::detect_platform() {
        return TeeType::Virtcca;
    }

    TeeType::Invalid
}

#[async_trait]
pub trait AttestationAgentAPIs {
    async fn get_challenge(&self, user_data: Option<Vec<u8>>) -> Result<String>;

    /// `get_evidence`: get hardware TEE signed evidence due to given user_data,
    /// such as input random challenge to prevent replay attacks
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>>;

    /// `verify_evidence`: verify the integrity of TEE evidence and evaluate the
    /// claims against the supplied reference values
    async fn verify_evidence(
        &self,
        challenge: &[u8],
        evidence: &[u8],
        policy_id: Option<Vec<String>>,
    ) -> Result<TeeClaim>;

    //#[cfg(not(feature = "no_as"))]
    async fn get_token(&self, user_data: TokenRequest) -> Result<String>;

    async fn verify_token(&self, token: String) -> Result<AsTokenClaim>;

    async fn get_resource(
        &self,
        challenge: &str,
        restful: &str,
        resource: ResourceLocation,
        token: &str,
    ) -> Result<String>;
}

#[async_trait]
impl AttestationAgentAPIs for AttestationAgent {
    // no_as generate by agent; has as generate by as
    async fn get_challenge(&self, user_data: Option<Vec<u8>>) -> Result<String> {
        #[cfg(feature = "no_as")]
        return self.generate_challenge_local(user_data).await;

        #[cfg(not(feature = "no_as"))]
        return self.get_challenge_from_as(user_data).await;
    }
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>> {
        Attester::default().tee_get_evidence(user_data).await
    }
    async fn verify_evidence(
        &self,
        challenge: &[u8],
        evidence: &[u8],
        _policy_id: Option<Vec<String>>,
    ) -> Result<TeeClaim> {
        #[cfg(feature = "no_as")]
        {
            let ret = Verifier::default()
                .verify_evidence(challenge, evidence)
                .await;
            match ret {
                Ok(tee_claim) => Ok(tee_claim),
                Err(e) => {
                    log::error!(
                        "attestation agent verify evidence with no as failed:{:?}",
                        e
                    );
                    Err(e)
                }
            }
        }

        #[cfg(not(feature = "no_as"))]
        {
            let ret = self
                .verify_evidence_by_as(challenge, evidence, _policy_id)
                .await;
            match ret {
                Ok(token) => self.token_to_teeclaim(token).await,
                Err(e) => {
                    log::error!("verify evidence with as failed:{:?}", e);
                    Err(e)
                }
            }
        }
    }

    async fn get_token(&self, user_data: TokenRequest) -> Result<String> {
        #[cfg(feature = "no_as")]
        {
            return Ok("no as in not support get token".to_string());
        }
        // todo token 有效期内，不再重新获取报告
        #[cfg(not(feature = "no_as"))]
        {
            let evidence = self.get_evidence(user_data.ev_req.clone()).await?;
            let challenge = &user_data.ev_req.challenge;
            let policy_id = user_data.policy_id;
            // request as
            return self
                .verify_evidence_by_as(challenge, &evidence, policy_id)
                .await;
        }
    }

    async fn verify_token(&self, token: String) -> Result<AsTokenClaim> {
        let verifier = TokenVerifier::new(self.config.get_token_cfg().clone())?;
        let result = verifier.verify(&token)?;
        Ok(result)
    }

    async fn get_resource(
        &self,
        challenge: &str,
        restful: &str,
        resource: ResourceLocation,
        token: &str,
    ) -> Result<String> {
        #[cfg(feature = "no_as")]
        {
            bail!("resource can only be gotten from attestation server!")
        }
        let rest = self
            .get_resource_from_as(challenge, restful, resource, token)
            .await?;
        Ok(String::from_utf8(rest.to_vec())?)
    }
}

#[derive(Clone)]
pub struct AttestationAgent {
    pub config: AAConfig,
    as_client_sessions: SessionMap,
}

#[allow(dead_code)]
impl AttestationAgent {
    pub fn new(config: AAConfig) -> Result<Self, Error> {
        let enable_active_attestation = config.enable_active_attestation;
        Self::new_with_interval(config, enable_active_attestation)
    }

    pub fn new_with_interval(
        config: AAConfig,
        enable_active_attestation: bool,
    ) -> Result<Self, Error> {
        let as_client_sessions = SessionMap::new();
        let sessions = as_client_sessions.clone();

        // Start session cleanup task
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                sessions
                    .session_map
                    .retain_async(|_, v| !v.is_expired())
                    .await;
            }
        });

        #[cfg(feature = "virtcca-attester")]
        let mut config = config;
        #[cfg(not(feature = "virtcca-attester"))]
        let config = config;

        #[cfg(feature = "virtcca-attester")]
        for app in &mut config.app_list {
            if app.rim_auto_discover || app.uuid == "auto" {
                if attester::virtcca::detect_platform() {
                    match attester::virtcca::discover_rim() {
                        Ok(rim_hex) => {
                            log::info!("Auto-discovered rim: {}", rim_hex);
                            app.uuid = rim_hex.clone();
                            let _ = app.discovered_rim.set(rim_hex);
                        }
                        Err(e) => {
                            if app.uuid == "auto" {
                                return Err(Error::Agent {
                                    source: AgentError::GetEvidenceError(format!(
                                        "Rim auto-discovery failed: {}",
                                        e
                                    )),
                                });
                            }
                            log::warn!("Rim auto-discovery failed, using configured uuid: {:?}", e);
                        }
                    }
                } else if app.uuid == "auto" {
                    return Err(Error::Agent {
                        source: AgentError::GetEvidenceError(
                            "uuid='auto' requires virtCCA platform".to_string(),
                        ),
                    });
                }
            }
        }

        #[cfg(not(feature = "virtcca-attester"))]
        for app in &config.app_list {
            if app.uuid == "auto" {
                return Err(Error::Agent {
                    source: AgentError::GetEvidenceError(
                        "uuid='auto' requires virtcca-attester feature".to_string(),
                    ),
                });
            }
        }

        let app_list = config.app_list.clone();

        let agent = AttestationAgent {
            config,
            as_client_sessions,
        };

        if enable_active_attestation {
            for app in &app_list {
                if app.interval > 0 {
                    let agent_clone = agent.clone();
                    let app_clone = app.clone();
                    tokio::spawn(async move {
                        // Add random delay betwenn [0, 1) seconds to avoid all tasks starting at the same time
                        let delay = rand::thread_rng().gen_range(0..1);
                        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                        agent_clone.start_active_attestation(&app_clone).await;
                    });
                } else {
                    log::warn!(
                        "Attestation interval is 0, skipping active attestation task {}",
                        app.uuid
                    );
                }
            }
        } else {
            log::debug!("Active attestation disabled, skipping active attestation task");
        }

        Ok(agent)
    }

    /// Start active attestation task with dynamic timer
    async fn start_active_attestation(&self, config: &AppConfig) {
        // 安全检查：确保 interval 大于 0
        let interval = if config.interval > 0 {
            config.interval
        } else {
            log::error!("Invalid attestation interval: {}", config.interval);
            return; // 提前返回，避免无限循环
        };

        log::info!(
            "Starting active attestation for {} with interval {} seconds",
            config.uuid,
            interval
        );

        loop {
            // 计算下次刷新延迟
            let next_refresh_delay = self.calculate_refresh_delay(config).await;

            log::debug!(
                "Next refresh for {} in {} seconds",
                config.uuid,
                next_refresh_delay
            );

            // 等待到刷新时间（使用 sleep_until 提高精度）
            if next_refresh_delay > 0 {
                let target_time = tokio::time::Instant::now()
                    + std::time::Duration::from_secs(next_refresh_delay);
                tokio::time::sleep_until(target_time).await;
            }

            // 双重检查：确保真的需要刷新
            if config.should_refresh_token().await {
                self.perform_token_refresh(config).await;
            }
        }
    }

    /// 计算下次刷新延迟时间
    async fn calculate_refresh_delay(&self, config: &AppConfig) -> u64 {
        if let Some(ttl) = config.get_token_ttl().await {
            if ttl <= 0 {
                0 // 已过期，立即刷新
            } else {
                let refresh_threshold = std::cmp::max(config.interval, (ttl as f64 * 0.1) as u64);
                std::cmp::max(1, ttl - refresh_threshold as i64) as u64
            }
        } else {
            0 // 没有 Token，立即刷新
        }
    }

    /// 执行 Token 刷新
    async fn perform_token_refresh(&self, config: &AppConfig) {
        if config.is_token_expired().await {
            log::info!("Token for {} has expired, refreshing", config.uuid);
        } else {
            let ttl = config.get_token_ttl().await.unwrap_or(0);
            log::info!(
                "Token for {} will expire in {} seconds, refreshing proactively",
                config.uuid,
                ttl
            );
        }

        match self.perform_active_attestation(config).await {
            Ok(token) => {
                if let Err(e) = config.store_token(token).await {
                    log::error!("Failed to store token for {}: {:?}", config.uuid, e);
                    config.record_failure();
                } else {
                    config.reset_failures();
                    log::info!("Token refreshed successfully for {}", config.uuid);
                }
            }
            Err(e) => {
                config.record_failure();
                let failure_count = config.get_failure_count();
                log::error!(
                    "Token refresh failed for {} (attempt {}): {:?}",
                    config.uuid,
                    failure_count,
                    e
                );

                // 智能重试延迟
                let max_consecutive_failures = 5;
                let max_delay = config.interval * 2;
                let delay = if failure_count >= max_consecutive_failures {
                    log::warn!(
                        "Too many consecutive failures for {}, using longer delay",
                        config.uuid
                    );
                    config.interval * 2
                } else {
                    std::cmp::min(10 * (2_u64.pow(failure_count - 1)), max_delay)
                };

                tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            }
        }
    }

    /// Perform active attestation: get challenge, evidence, and verify with AS
    async fn perform_active_attestation(&self, config: &AppConfig) -> Result<String> {
        // Generate a random challenge
        // let challenge_data: [u8; 32] = rand::random();
        // let challenge = base64_url::encode(&challenge_data);
        // Get challenge from AS
        let challenge_from_as = self.get_challenge_from_as(None).await?;
        let encoded_challenge = challenge_from_as.as_bytes().to_vec();

        // Create evidence request from AppConfig
        let evidence_request = EvidenceRequest {
            uuid: config.uuid.clone(),
            challenge: encoded_challenge.clone(),
            ima: Some(config.ima), // Enable IMA for active attestation
        };
        log::debug!(
            "Created evidence request: uuid={}, ima={:?}",
            evidence_request.uuid,
            evidence_request.ima
        );

        // Get evidence from TEE
        log::info!("Calling get_evidence from TEE");
        let evidence = match self.get_evidence(evidence_request).await {
            Ok(evidence) => {
                log::info!(
                    "Successfully obtained evidence from TEE: {} bytes",
                    evidence.len()
                );
                evidence
            }
            Err(e) => {
                log::error!("Failed to get evidence from TEE: {:?}", e);
                return Err(e);
            }
        };

        // Verify evidence with attestation service, currently only default policy is supported
        // #[cfg(not(feature = "no_as"))]
        let token = match self
            .verify_evidence_by_as(&encoded_challenge, &evidence, None)
            .await
        {
            Ok(token) => {
                log::info!(
                    "Successfully verified evidence with AS, token length: {}",
                    token.len()
                );
                token
            }
            Err(e) => {
                log::error!("Failed to verify evidence with AS: {:?}", e);
                return Err(e);
            }
        };

        Ok(token)
    }

    fn create_client(&self, protocal: HttpProtocal, cookie_store: bool) -> Result<reqwest::Client> {
        let client: Client = match protocal {
            HttpProtocal::Http { protocal: _ } => reqwest::Client::builder()
                .cookie_store(cookie_store)
                .build()?,
            HttpProtocal::Https {
                protocal: _,
                cert_root,
            } => {
                let cert = reqwest::Certificate::from_pem(cert_root.as_bytes())?;
                reqwest::Client::builder()
                    .cookie_store(cookie_store)
                    .add_root_certificate(cert)
                    .build()?
            }
        };

        Ok(client)
    }

    #[cfg(not(feature = "no_as"))]
    async fn verify_evidence_by_as(
        &self,
        challenge: &[u8],
        evidence: &[u8],
        policy_id: Option<Vec<String>>,
    ) -> Result<String> {
        log::info!("Starting verify_evidence_by_as");
        log::debug!(
            "Challenge length: {} bytes, Evidence length: {} bytes, policy_id: {:?}",
            challenge.len(),
            evidence.len(),
            policy_id
        );

        let challenge = String::from_utf8_lossy(challenge).to_string();
        log::debug!("Challenge string: {}", challenge);

        let ss = self
            .as_client_sessions
            .session_map
            .get_async(&challenge)
            .await;
        log::debug!("Session lookup result: {:?}", ss.is_some());

        let request_body = json!({
            "challenge": challenge,
            "evidence": base64_url::encode(evidence),
            "policy_id": policy_id,
        });
        log::debug!(
            "Request body prepared: challenge={}, evidence_length={}",
            challenge,
            evidence.len()
        );

        let mut map = HeaderMap::new();
        let client;
        if ss.is_none() {
            log::debug!("No existing session, creating new client");
            client = match self.create_client(self.config.protocal.clone(), true) {
                Ok(client) => {
                    log::debug!("Client created successfully");
                    client
                }
                Err(e) => {
                    log::error!("Failed to create client: {:?}", e);
                    return Err(e);
                }
            };
            map.insert("Content-Type", HeaderValue::from_static("application/json"));
        } else {
            log::debug!("Using existing session");
            // If the session is already attested, directly use the token.
            if let Some(t) = ss.as_ref().unwrap().get().token.as_ref() {
                log::info!("Using cached token from existing session");
                return Ok(t.clone());
            }
            map.insert("Content-Type", HeaderValue::from_static("application/json"));
            map.insert("as-challenge", HeaderValue::from_static("as"));
            client = ss.as_ref().unwrap().get().as_client.clone();
            log::debug!("Using client from existing session");
        }

        let attest_endpoint = format!("{}/attestation", self.config.svr_url);
        log::info!(
            "Sending request to attestation endpoint: {}",
            attest_endpoint
        );
        log::debug!("Request headers: {:?}", map);

        let res = match client
            .post(&attest_endpoint)
            .headers(map)
            .json(&request_body)
            .send()
            .await
        {
            Ok(res) => {
                log::debug!("Request sent successfully, status: {}", res.status());
                res
            }
            Err(e) => {
                log::error!("Failed to send request: {:?}", e);
                return Err(anyhow::anyhow!("Request failed: {:?}", e));
            }
        };

        match res.status() {
            reqwest::StatusCode::OK => {
                log::info!("Received successful response from attestation service");
                let token = match res.text().await {
                    Ok(token) => {
                        log::debug!("Response text extracted, length: {}", token.len());
                        token
                    }
                    Err(e) => {
                        log::error!("Failed to extract response text: {:?}", e);
                        return Err(anyhow::anyhow!("Failed to read response: {:?}", e));
                    }
                };

                if ss.as_ref().is_some() {
                    // 使用正确的方式访问session
                    if let Some(_session) = ss.as_ref() {
                        // 直接访问session的token字段
                        log::debug!("Session exists, but cannot modify token in this context");
                        // 注意：这里无法直接修改session的token，因为get()返回的是不可变引用
                        // 如果需要修改token，需要在session创建时就设置好
                    }
                }
                log::info!("Remote Attestation success, token length: {}", token.len());
                Ok(token)
            }
            _ => {
                let status = res.status();
                let error_text = match res.text().await {
                    Ok(text) => text,
                    Err(e) => format!("Failed to read error response: {:?}", e),
                };
                log::error!(
                    "Remote Attestation Failed, Status: {}, Response: {}",
                    status,
                    error_text
                );
                bail!(
                    "Remote Attestation Failed, Status: {}, AS Response: {}",
                    status,
                    error_text
                );
            }
        }
    }

    #[cfg(not(feature = "no_as"))]
    async fn token_to_teeclaim(&self, token: String) -> Result<TeeClaim> {
        let ret = self.verify_token(token).await;
        match ret {
            Ok(token) => {
                let token_claim: serde_json::Value =
                    serde_json::from_slice(token.claim.as_bytes())?;
                Ok(token_claim as TeeClaim)
            }
            Err(e) => {
                log::error!("token to teeclaim failed:{:?}", e);
                Err(e)
            }
        }
    }

    async fn generate_challenge_local(&self, user_data: Option<Vec<u8>>) -> Result<String> {
        let mut nonce: Vec<u8> = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        if let Some(mut data) = user_data {
            nonce.append(&mut data);
        }
        Ok(base64_url::encode(&nonce))
    }

    async fn get_challenge_from_as(&self, user_data: Option<Vec<u8>>) -> Result<String> {
        let challenge_endpoint = format!("{}/challenge", self.config.svr_url);
        let client = self.create_client(self.config.protocal.clone(), true)?;
        let data: Value = if user_data.is_some() {
            json!({"user_data":user_data.unwrap()})
        } else {
            Value::Null
        };
        let res = client
            .get(challenge_endpoint)
            .header("Content-Type", "application/json")
            .body(data.to_string())
            .send()
            .await?;

        let challenge = match res.status() {
            reqwest::StatusCode::OK => {
                let respone: String = res.json().await.unwrap();
                log::debug!("get challenge success, AS Response: {:?}", respone);
                respone
            }
            status => {
                log::error!("get challenge Failed, AS Response: {:?}", status);
                bail!("get challenge Failed")
            }
        };
        let session = Session::new(challenge.clone(), client, SESSION_TIMEOUT_MIN)?;
        self.as_client_sessions.insert(session);
        Ok(challenge)
    }

    async fn get_resource_from_as(
        &self,
        challenge: &str,
        restful: &str,
        resource: ResourceLocation,
        token: &str,
    ) -> Result<Bytes> {
        // Use the client in the attested session to
        let session = match self
            .as_client_sessions
            .session_map
            .get_async(challenge)
            .await
        {
            Some(s) => s,
            None => bail!("getting resource failed because the session is missing"),
        };

        let payload = GetResourceOp::TeeGet { resource };

        let response = session
            .get()
            .as_client
            .get(restful)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await?;
        let resource = match response.status() {
            reqwest::StatusCode::OK => {
                let respone = response.bytes().await.unwrap();
                log::debug!("get resource success, AS Response: {:?}", respone);
                respone
            }
            status => {
                log::error!("get resource Failed, AS Response: {:?}", status);
                bail!("get resource Failed")
            }
        };

        Ok(resource)
    }

    // 获取特定应用的 token
    pub async fn get_app_token(&self, app_uuid: &str) -> Option<String> {
        if let Some(app) = self.config.app_list.iter().find(|app| app.uuid == app_uuid) {
            app.get_token().await
        } else {
            None
        }
    }

    // 检查应用是否有有效 token
    pub async fn has_app_token(&self, app_uuid: &str) -> bool {
        if let Some(app) = self.config.app_list.iter().find(|app| app.uuid == app_uuid) {
            app.has_token().await
        } else {
            false
        }
    }

    // 获取应用 token 信息（用于监控）
    pub async fn get_app_token_info(&self, app_uuid: &str) -> Option<serde_json::Value> {
        if let Some(app) = self.config.app_list.iter().find(|app| app.uuid == app_uuid) {
            Some(serde_json::json!({
                "has_token": app.has_token().await,
                "expires_at": app.get_token_expires_at().await,
                "ttl_seconds": app.get_token_ttl().await,
                "failure_count": app.get_failure_count(),
                "is_expired": app.is_token_expired().await
            }))
        } else {
            None
        }
    }

    fn select_active_token_app(
        &self,
        uuid: Option<&str>,
        runtime_platform: TeeType,
    ) -> std::result::Result<Option<&AppConfig>, ActiveTokenError> {
        if self.config.app_list.is_empty() {
            return if uuid.is_some() {
                Err(ActiveTokenError::AppNotFound)
            } else {
                Ok(None)
            };
        }

        match runtime_platform {
            TeeType::Itrustee => {
                let app = if let Some(uuid) = uuid {
                    if uuid == "auto" {
                        return Err(ActiveTokenError::InvalidUuid);
                    }

                    let mut matches = self.config.app_list.iter().filter(|app| app.uuid == uuid);
                    let first = matches.next().ok_or(ActiveTokenError::AppNotFound)?;
                    if matches.next().is_some() {
                        return Err(ActiveTokenError::AmbiguousApp);
                    }
                    first
                } else {
                    self.config
                        .app_list
                        .first()
                        .ok_or(ActiveTokenError::AppNotFound)?
                };

                if app.platform != TeeType::Itrustee {
                    return Err(ActiveTokenError::PlatformMismatch);
                }

                Ok(Some(app))
            }
            TeeType::Virtcca => {
                let app = self
                    .config
                    .app_list
                    .first()
                    .ok_or(ActiveTokenError::AppNotFound)?;

                if app.platform != TeeType::Virtcca && app.platform != TeeType::Invalid {
                    return Err(ActiveTokenError::PlatformMismatch);
                }

                if let Some(uuid) = uuid {
                    if uuid == "auto" {
                        return Err(ActiveTokenError::InvalidUuid);
                    }
                    if app.configured_uuid() == "auto" || app.configured_uuid() != uuid {
                        return Err(ActiveTokenError::AppNotFound);
                    }
                }

                Ok(Some(app))
            }
            _ => Err(ActiveTokenError::TeeUnavailable),
        }
    }

    pub async fn get_active_token(
        &self,
        uuid: Option<&str>,
        nonce: Option<Vec<u8>>,
    ) -> std::result::Result<ActiveTokenResponse, ActiveTokenError> {
        let runtime_platform = detect_active_token_runtime_platform();
        self.get_active_token_with_platform(uuid, nonce, runtime_platform)
            .await
    }

    pub(crate) async fn get_active_token_with_platform(
        &self,
        uuid: Option<&str>,
        nonce: Option<Vec<u8>>,
        runtime_platform: TeeType,
    ) -> std::result::Result<ActiveTokenResponse, ActiveTokenError> {
        match runtime_platform {
            TeeType::Itrustee => {
                if nonce.is_some() {
                    return Err(ActiveTokenError::NotSupported);
                }
            }
            TeeType::Virtcca => {
                if nonce.is_none() {
                    return Err(ActiveTokenError::MissingNonce);
                }
            }
            _ => return Err(ActiveTokenError::TeeUnavailable),
        }

        let app = self.select_active_token_app(uuid, runtime_platform.clone())?;
        let Some(app) = app else {
            return Err(ActiveTokenError::NoTokenAvailable);
        };

        let jwt_token = app.get_token().await;
        let expires_at = app.get_token_expires_at().await;
        let ttl_seconds = app.get_token_ttl().await;
        let failure_count = app.get_failure_count();

        if jwt_token.is_none() {
            return Err(ActiveTokenError::NoTokenAvailable);
        }

        let (cvm_token, dev_cert) = match runtime_platform {
            TeeType::Virtcca => self.get_virtcca_token_for_nonce(nonce.unwrap()).await?,
            _ => (None, None),
        };

        Ok(ActiveTokenResponse {
            jwt_token,
            expires_at,
            ttl_seconds,
            cvm_token,
            dev_cert,
            error: None,
            failure_count,
        })
    }

    #[cfg(feature = "virtcca-attester")]
    async fn get_virtcca_token_for_nonce(
        &self,
        nonce_bytes: Vec<u8>,
    ) -> std::result::Result<(Option<String>, Option<String>), ActiveTokenError> {
        let result = tokio::task::spawn_blocking(move || {
            attester::virtcca::tee_get_token_only(&nonce_bytes)
        })
        .await
        .map_err(|_| ActiveTokenError::TeeUnavailable)?
        .map_err(|_| ActiveTokenError::TeeUnavailable)?;
        Ok((
            Some(BASE64_STANDARD.encode(&result.0)),
            Some(BASE64_STANDARD.encode(&result.1)),
        ))
    }

    #[cfg(not(feature = "virtcca-attester"))]
    async fn get_virtcca_token_for_nonce(
        &self,
        _nonce_bytes: Vec<u8>,
    ) -> std::result::Result<(Option<String>, Option<String>), ActiveTokenError> {
        Err(ActiveTokenError::NotSupported)
    }
}

// attestation agent c interface
use safer_ffi::prelude::*;
use tokio::runtime::Runtime;

#[ffi_export]
pub fn init_env_logger(c_level: Option<&repr_c::String>) {
    let level = match c_level {
        Some(level) => level,
        None => "info",
    };
    env_logger::init_from_env(env_logger::Env::new().default_filter_or(level));
}

#[ffi_export]
pub fn get_report(
    c_challenge: Option<&repr_c::Vec<u8>>,
    c_ima: &repr_c::TaggedOption<bool>,
    c_uuid: &repr_c::String,
) -> repr_c::Vec<u8> {
    log::debug!("input challenge: {:?}, ima: {:?}", c_challenge, c_ima);
    let ima = match c_ima {
        repr_c::TaggedOption::None => false,
        repr_c::TaggedOption::Some(ima) => *ima,
    };
    let challenge = match c_challenge {
        None => {
            log::error!("challenge is null");
            return Vec::new().into();
        }
        Some(cha) => cha.clone().to_vec(),
    };

    let input: EvidenceRequest = EvidenceRequest {
        uuid: c_uuid.to_string(),
        challenge: challenge,
        ima: Some(ima),
    };
    let rt = Runtime::new().unwrap();
    let config = AAConfig::try_from(Path::new(DEFAULT_AACONFIG_FILE)).unwrap();
    let fut = async {
        AttestationAgent::new(config)
            .unwrap()
            .get_evidence(input)
            .await
    };
    let ret = rt.block_on(fut);
    let report: Vec<u8> = match ret {
        Ok(report) => report,
        Err(e) => {
            log::error!("get report failed {:?}", e);
            Vec::new()
        }
    };

    report.into()
}

#[cfg(feature = "no_as")]
#[ffi_export]
pub fn parse_report(report: Option<&repr_c::Vec<u8>>) -> repr_c::String {
    let report = match report {
        None => {
            log::error!("report is null");
            return "".to_string().into();
        }
        Some(report) => report.clone().to_vec(),
    };
    let rt = Runtime::new().unwrap();
    let fut = async { virtcca_parse_evidence(&report) };
    let ret = rt.block_on(fut);

    let ret = match ret {
        Ok(claim) => {
            log::debug!("claim: {:?}", claim);
            claim.to_string()
        }
        Err(e) => {
            log::error!("{e}");
            "".to_string()
        }
    };

    return ret.into();
}

#[ffi_export]
pub fn verify_report(
    c_challenge: Option<&repr_c::Vec<u8>>,
    report: Option<&repr_c::Vec<u8>>,
) -> repr_c::String {
    let challenge = match c_challenge {
        None => {
            log::error!("challenge is null");
            return "".to_string().into();
        }
        Some(cha) => cha.clone().to_vec(),
    };
    let report = match report {
        None => {
            log::error!("report is null");
            return "".to_string().into();
        }
        Some(report) => report.clone().to_vec(),
    };
    let rt = Runtime::new().unwrap();
    let config = AAConfig::try_from(Path::new(DEFAULT_AACONFIG_FILE)).unwrap();
    let fut = async {
        AttestationAgent::new(config)
            .unwrap()
            .verify_evidence(&challenge, &report, None)
            .await
    };
    let ret = rt.block_on(fut);

    let ret = match ret {
        Ok(claim) => {
            log::debug!("claim: {:?}", claim);
            claim.to_string()
        }
        Err(e) => {
            log::error!("{e}");
            "".to_string()
        }
    };

    return ret.into();
}

#[ffi_export]
pub fn free_rust_vec(vec: repr_c::Vec<u8>) {
    drop(vec);
}

// The following function is only necessary for the header generation.
#[cfg(feature = "headers")]
pub fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder()
        .to_file("./c_header/rust_attestation_agent.h")?
        .generate()
}

#[cfg(all(test, not(feature = "virtcca-attester")))]
mod tests {
    use super::*;
    use attestation_types::TeeType;

    #[tokio::test]
    async fn uuid_auto_requires_virtcca_attester_feature() {
        let mut config = AAConfig::default();
        config.app_list.push(AppConfig::new(
            "auto".to_string(),
            true,
            30,
            TeeType::Virtcca,
            true,
        ));

        let result = AttestationAgent::new(config);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod active_token_tests {
    use super::*;
    use attestation_types::TeeType;

    fn fake_jwt(label: &str) -> String {
        let header = base64_url::encode(r#"{"alg":"none"}"#);
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = base64_url::encode(&format!(r#"{{"exp":{exp},"label":"{label}"}}"#));
        format!("{header}.{payload}.signature")
    }

    fn agent_with_apps(apps: Vec<AppConfig>) -> AttestationAgent {
        let mut config = AAConfig::default();
        config.app_list = apps;
        AttestationAgent {
            config,
            as_client_sessions: SessionMap::new(),
        }
    }

    #[tokio::test]
    async fn itrustee_active_token_can_select_cached_token_by_uuid() {
        let agent = agent_with_apps(vec![
            AppConfig::new("ta-1".to_string(), true, 30, TeeType::Itrustee, false),
            AppConfig::new("ta-2".to_string(), true, 30, TeeType::Itrustee, false),
        ]);
        let expected = fake_jwt("ta-2");
        agent.config.app_list[1]
            .store_token(expected.clone())
            .await
            .unwrap();

        let response = agent
            .get_active_token_with_platform(Some("ta-2"), None, TeeType::Itrustee)
            .await
            .unwrap();

        assert_eq!(response.jwt_token, Some(expected));
    }

    #[tokio::test]
    async fn itrustee_active_token_rejects_duplicate_uuid() {
        let agent = agent_with_apps(vec![
            AppConfig::new("same-ta".to_string(), true, 30, TeeType::Itrustee, false),
            AppConfig::new("same-ta".to_string(), true, 30, TeeType::Itrustee, false),
        ]);

        let error = agent
            .get_active_token_with_platform(Some("same-ta"), None, TeeType::Itrustee)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::AmbiguousApp);
    }

    #[tokio::test]
    async fn itrustee_active_token_rejects_auto_uuid() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "ta-1".to_string(),
            true,
            30,
            TeeType::Itrustee,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(Some("auto"), None, TeeType::Itrustee)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::InvalidUuid);
    }

    #[tokio::test]
    async fn itrustee_active_token_returns_not_found_for_unknown_uuid() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "ta-1".to_string(),
            true,
            30,
            TeeType::Itrustee,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(Some("missing-ta"), None, TeeType::Itrustee)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::AppNotFound);
    }

    #[tokio::test]
    async fn itrustee_nonce_is_not_supported_before_token_lookup() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "ta-1".to_string(),
            true,
            30,
            TeeType::Itrustee,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(Some("ta-1"), Some(vec![0u8; 32]), TeeType::Itrustee)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::NotSupported);
    }

    #[tokio::test]
    async fn itrustee_active_token_requires_cached_token() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "ta-1".to_string(),
            true,
            30,
            TeeType::Itrustee,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(Some("ta-1"), None, TeeType::Itrustee)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::NoTokenAvailable);
    }

    #[tokio::test]
    async fn empty_itrustee_app_list_still_rejects_nonce() {
        let agent = agent_with_apps(vec![]);

        let error = agent
            .get_active_token_with_platform(None, Some(vec![0u8; 32]), TeeType::Itrustee)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::NotSupported);
    }

    #[tokio::test]
    async fn empty_virtcca_app_list_still_requires_nonce() {
        let agent = agent_with_apps(vec![]);

        let error = agent
            .get_active_token_with_platform(None, None, TeeType::Virtcca)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::MissingNonce);
    }

    #[tokio::test]
    async fn virtcca_active_token_requires_nonce() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "rim-1".to_string(),
            false,
            30,
            TeeType::Virtcca,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(None, None, TeeType::Virtcca)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::MissingNonce);
    }

    #[tokio::test]
    async fn virtcca_active_token_rejects_auto_uuid_query() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "rim-1".to_string(),
            false,
            30,
            TeeType::Virtcca,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(Some("auto"), Some(vec![0u8; 32]), TeeType::Virtcca)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::InvalidUuid);
    }

    #[tokio::test]
    async fn virtcca_uuid_query_matches_configured_uuid_before_token_lookup() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "rim-1".to_string(),
            false,
            30,
            TeeType::Virtcca,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(Some("rim-1"), Some(vec![0u8; 32]), TeeType::Virtcca)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::NoTokenAvailable);
    }

    #[tokio::test]
    async fn virtcca_uuid_query_does_not_match_auto_config_after_discovery() {
        let mut app = AppConfig::new("auto".to_string(), false, 30, TeeType::Virtcca, true);
        app.uuid = "discovered-rim".to_string();
        let agent = agent_with_apps(vec![app]);

        let error = agent
            .get_active_token_with_platform(
                Some("discovered-rim"),
                Some(vec![0u8; 32]),
                TeeType::Virtcca,
            )
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::AppNotFound);
    }

    #[tokio::test]
    async fn selected_app_platform_must_match_runtime_platform() {
        let agent = agent_with_apps(vec![AppConfig::new(
            "rim-1".to_string(),
            false,
            30,
            TeeType::Virtcca,
            false,
        )]);

        let error = agent
            .get_active_token_with_platform(None, None, TeeType::Itrustee)
            .await
            .unwrap_err();

        assert_eq!(error, ActiveTokenError::PlatformMismatch);
    }
}
