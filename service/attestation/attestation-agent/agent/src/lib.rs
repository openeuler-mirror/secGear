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

//! Attestation Agent
//!
//! This crate provides some APIs to get and verify the TEE evidence.
//! Current supports kunpeng itrustee and virtcca TEE types.

pub mod restapi;
pub mod result;

use actix_web::web::Bytes;
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use attestation_types::{resource::ResourceLocation, service::GetResourceOp};
use attester::{Attester, AttesterAPIs};
use log;
use rand::RngCore;
use reqwest::Client;
use result::Error;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use std::fs::File;
use std::path::Path;
use thiserror;
use token_verifier::{TokenRawData, TokenVerifier, TokenVerifyConfig};
use std::sync::Arc;
use std::sync::Mutex;

pub type TeeClaim = serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("challenge error: {0}")]
    ChallengeError(String),
    #[error("get evidence error: {0}")]
    DecodeError(String),
    #[error("get evidence error: {0}")]
    GetEvidenceError(String),
    #[error("verify evidence error: {0}")]
    VerifyEvidenceError(String),
    #[error("get token error: {0}")]
    GetTokenError(String),
    #[error("verify token error: {0}")]
    VerifyTokenError(String),
}

#[cfg(feature = "no_as")]
use verifier::{Verifier, VerifierAPIs};

#[cfg(not(feature = "no_as"))]
use {
    base64_url,
    reqwest::header::{HeaderMap, HeaderValue},
};

pub use attester::EvidenceRequest;
mod session;
use attestation_types::SESSION_TIMEOUT_MIN;
use session::{Session, SessionMap};

pub type AsTokenClaim = TokenRawData;

pub const DEFAULT_AACONFIG_FILE: &str = "/etc/attestation/attestation-agent/attestation-agent.conf";
pub struct TokenRequest {
    pub ev_req: EvidenceRequest,
    pub policy_id: Option<Vec<String>>,
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
        let verifier = TokenVerifier::new(self.config.token_cfg.clone())?;
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
pub struct AAConfig {
    // Attestation Service url
    pub svr_url: String,
    // Http protocal, such as http or https
    pub protocal: HttpProtocal,
    token_cfg: TokenVerifyConfig,
}

impl Default for AAConfig {
    fn default() -> Self {
        Self {
            svr_url: String::from("http://127.0.0.1:8080"),
            token_cfg: TokenVerifyConfig::default(),
            protocal: HttpProtocal::default(),
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
        serde_json::from_reader::<File, AAConfig>(file).map_err(|e| anyhow!("invalid aaconfig {e}"))
    }
}

#[derive(Clone)]
pub struct AttestationAgent {
    pub config: AAConfig,
    as_client_sessions: SessionMap,
    attestation_interval: Option<u64>,
    current_token: Arc<Mutex<Option<String>>>,
}

#[allow(dead_code)]
impl AttestationAgent {
    pub fn new(config: AAConfig) -> Result<Self, Error> {
        Self::new_with_interval(config, None)
    }

    pub fn new_with_interval(config: AAConfig, attestation_interval: Option<u64>) -> Result<Self, Error> {
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

        let agent = AttestationAgent {
            config,
            as_client_sessions,
            attestation_interval,
            current_token: Arc::new(Mutex::new(None)),
        };

        // Start active attestation task if interval is specified
        if let Some(interval) = attestation_interval {
            if interval > 0 {
                let agent_clone = agent.clone();
                tokio::spawn(async move {
                    agent_clone.start_active_attestation().await;
                });
            } else {
                log::warn!("Attestation interval is 0, skipping active attestation task");
            }
        } else {
            log::debug!("No attestation interval specified, skipping active attestation task");
        }

        Ok(agent)
    }

    /// Start active attestation task
    async fn start_active_attestation(&self) {
        // 安全检查：确保 attestation_interval 不为 None
        let interval = match self.attestation_interval {
            Some(interval) if interval > 0 => interval,
            _ => {
                log::error!("Invalid attestation interval: {:?}", self.attestation_interval);
                return; // 提前返回，避免无限循环
            }
        };
        
        log::info!("Starting active attestation with interval {} seconds", interval);
        
        let mut iteration_count = 0;
        let mut consecutive_failures = 0;
        
        loop {
            iteration_count += 1;
            log::info!("Active attestation iteration {} starting", iteration_count);
            
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            log::debug!("Sleep completed, proceeding with attestation");
            
            match self.perform_active_attestation().await {
                Ok(token) => {
                    log::info!("Active attestation successful, token obtained");
                    consecutive_failures = 0; // 重置失败计数
                    
                    // Store the token in the agent
                    match self.current_token.lock() {
                        Ok(mut token_guard) => {
                            *token_guard = Some(token);
                            log::debug!("Token stored successfully");
                        }
                        Err(e) => {
                            log::error!("Failed to store token: mutex lock failed: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    consecutive_failures += 1;
                    log::error!("Active attestation failed (attempt {}): {:?}", iteration_count, e);
                    log::error!("Consecutive failures: {}", consecutive_failures);
                    
                    // 如果连续失败次数过多，增加延迟
                    if consecutive_failures >= 3 {
                        log::warn!("Too many consecutive failures, adding extra delay");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                }
            }
            
            log::debug!("Active attestation iteration {} completed", iteration_count);
        }
    }

    /// Perform active attestation: get challenge, evidence, and verify with AS
    async fn perform_active_attestation(&self) -> Result<String> {

        
        // Generate a random challenge
        let challenge_data: [u8; 32] = rand::random();
        // rand::thread_rng().fill_bytes(&mut challenge_data);
        let _challenge = base64_url::encode(&challenge_data);
        let encoded_challenge = _challenge.into_bytes();
   
        
        // Create evidence request, use fixed uuid for testing.
        // TODO: allow user to set uuid
        let evidence_request = EvidenceRequest {
            uuid: "f68fd704-6eb1-4d14-b218-722850eb3ef0".to_string(),
            challenge: encoded_challenge.clone(),
            ima: Some(true), // Enable IMA for active attestation
        };
        log::debug!("Created evidence request: uuid={}, ima={:?}", evidence_request.uuid, evidence_request.ima);
        
        // Get evidence from TEE
        log::info!("Calling get_evidence from TEE");
        let evidence = match self.get_evidence(evidence_request).await {
            Ok(evidence) => {
                log::info!("Successfully obtained evidence from TEE: {} bytes", evidence.len());
                evidence
            }
            Err(e) => {
                log::error!("Failed to get evidence from TEE: {:?}", e);
                return Err(e);
            }
        };
        
        // Verify evidence with attestation service
        // #[cfg(not(feature = "no_as"))]
        let token = match self.verify_evidence_by_as(&encoded_challenge, &evidence, Some(vec!["0".to_string()])).await {
            Ok(token) => {
                log::info!("Successfully verified evidence with AS, token length: {}", token.len());
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
        log::debug!("Challenge length: {} bytes, Evidence length: {} bytes", challenge.len(), evidence.len());
        
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
        log::debug!("Request body prepared: challenge={}, evidence_length={}", challenge, evidence.len());
        
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
        log::info!("Sending request to attestation endpoint: {}", attest_endpoint);
        log::debug!("Request headers: {:?}", map);
        
        let res = match client
            .post(&attest_endpoint)
            .headers(map)
            .json(&request_body)
            .send()
            .await {
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
                log::error!("Remote Attestation Failed, Status: {}, Response: {}", status, error_text);
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
        if user_data != None {
            nonce.append(&mut user_data.unwrap());
        }
        Ok(base64_url::encode(&nonce))
    }

    async fn get_challenge_from_as(&self, user_data: Option<Vec<u8>>) -> Result<String> {
        let challenge_endpoint = format!("{}/challenge", self.config.svr_url);
        let client = self.create_client(self.config.protocal.clone(), true)?;
        let data: Value;
        if user_data.is_some() {
            data = json!({"user_data":user_data.unwrap()});
        } else {
            data = Value::Null;
        }
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
}

// attestation agent c interface
use safer_ffi::prelude::*;
use tokio::runtime::Runtime;

#[ffi_export]
pub fn init_env_logger(c_level: Option<&repr_c::String>) {
    let level = match c_level {
        Some(level) => &level,
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

#[cfg(all(feature = "no_as", feature = "parse_evidence"))]
use verifier::virtcca_parse_evidence;

#[cfg(all(feature = "no_as", feature = "parse_evidence"))]
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
