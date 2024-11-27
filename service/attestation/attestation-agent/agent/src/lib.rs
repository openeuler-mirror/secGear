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

use anyhow::{Result, bail, anyhow};
use log;
use reqwest::Client;
use serde::{Serialize, Deserialize};
use async_trait::async_trait;
use std::fs::File;
use std::path::Path;
use rand::RngCore;
use thiserror;

use attester::{Attester, AttesterAPIs};
use token_verifier::{TokenVerifyConfig, TokenVerifier, TokenRawData};

pub mod result;
use result::Error;
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
    serde_json::json,
    reqwest::header::{HeaderMap, HeaderValue},
    base64_url
};

pub use attester::EvidenceRequest;
mod session;
use session::{SessionMap, Session};
use attestation_types::SESSION_TIMEOUT_MIN;

pub type AsTokenClaim = TokenRawData;

pub const DEFAULT_AACONFIG_FILE: &str = "/etc/attestation/attestation-agent/attestation-agent.conf";
pub struct TokenRequest {
    pub ev_req: EvidenceRequest,
    pub policy_id: Option<Vec<String>>,
}

#[async_trait]
pub trait AttestationAgentAPIs {
    async fn get_challenge(&self) -> Result<String>;

    /// `get_evidence`: get hardware TEE signed evidence due to given user_data,
    /// such as input random challenge to prevent replay attacks
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>>;

    /// `verify_evidence`: verify the integrity of TEE evidence and evaluate the
    /// claims against the supplied reference values
    async fn verify_evidence(&self,
        challenge: &[u8],
        evidence: &[u8],
        policy_id: Option<Vec<String>>
    ) -> Result<TeeClaim>;

    //#[cfg(not(feature = "no_as"))]
    async fn get_token(&self, user_data: TokenRequest) -> Result<String>;

    async fn verify_token(&self, token: String) -> Result<AsTokenClaim>;
}

#[async_trait]
impl AttestationAgentAPIs for AttestationAgent {
    // no_as generate by agent; has as generate by as
    async fn get_challenge(&self) -> Result<String> {
        #[cfg(feature = "no_as")]
        return self.generate_challenge_local().await;

        #[cfg(not(feature = "no_as"))]
        return self.get_challenge_from_as().await;
    }
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>> {
        Attester::default().tee_get_evidence(user_data).await
    }
    async fn verify_evidence(&self,
        challenge: &[u8],
        evidence: &[u8],
        _policy_id: Option<Vec<String>>
    ) -> Result<TeeClaim> {
        #[cfg(feature = "no_as")]
        {
            let ret = Verifier::default().verify_evidence(challenge, evidence).await;
            match ret {
                Ok(tee_claim) => Ok(tee_claim),
                Err(e) => {
                    log::error!("attestation agent verify evidence with no as failed:{:?}", e);
                    Err(e)
                },
            }
        }

        #[cfg(not(feature = "no_as"))]
        {
            let ret = self.verify_evidence_by_as(challenge, evidence, _policy_id).await;
            match ret {
                Ok(token) => { self.token_to_teeclaim(token).await },
                Err(e) => {
                    log::error!("verify evidence with as failed:{:?}", e);
                    Err(e)
                },
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
            return self.verify_evidence_by_as(challenge, &evidence, policy_id).await;
        }
    }

    async fn verify_token(&self, token: String) -> Result<AsTokenClaim> {
        let verifier = TokenVerifier::new(self.config.token_cfg.clone())?;
        let result = verifier.verify(&token)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AAConfig {
    pub svr_url: String,             // Attestation Service url
    token_cfg: TokenVerifyConfig,
}

impl Default for AAConfig {
    fn default() -> Self {
        Self {
            svr_url: String::from("http://127.0.0.1:8080"),
            token_cfg: TokenVerifyConfig::default(),
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

#[derive(Debug)]
pub struct AttestationAgent {
    pub config: AAConfig,
    as_client_sessions: SessionMap,
    pub cert_root: String,
    pub access_as_protocol: String,
}

#[allow(dead_code)]
impl AttestationAgent {
    pub fn new(conf_path: Option<String>) -> Result<Self, Error> {
        let config = match conf_path {
            Some(conf_path) => {
                log::info!("Attestation Agent config file:{conf_path}");
                AAConfig::try_from(Path::new(&conf_path))?
            }
            None => {
                log::warn!("No Attestation Agent config file specified. Using a default config");
                AAConfig::default()
            }
        };
        let as_client_sessions = SessionMap::new();
        let sessions = as_client_sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                sessions
                    .session_map
                    .retain_async(|_, v| !v.is_expired())
                    .await;
            }
        });
        Ok(AttestationAgent {
            config,
            as_client_sessions,
            access_as_protocol: String::from("http"),
            cert_root: String::from("")
        })
    }

    fn create_client(protocol:String, cert:Option<String>, cookie_store:bool) -> Result<reqwest::Client> {
        let client:Client;
        if protocol == "https" {
            if cert == None {
                return Err(anyhow!("https need root certificate"));
            }
            let cert = reqwest::Certificate::from_pem(cert.unwrap().as_bytes())?;
            client = reqwest::Client::builder()
            .cookie_store(cookie_store)
            .add_root_certificate(cert)
            .build()?; 
        } else if protocol == "http" {
            client = reqwest::Client::builder()
            .cookie_store(cookie_store)
            .build()?;
        } else {
            return Err(anyhow!("unknown {}", protocol));
        }
        Ok(client)
    }

    #[cfg(not(feature = "no_as"))]
    async fn verify_evidence_by_as(&self,
        challenge: &[u8],
        evidence: &[u8],
        policy_id: Option<Vec<String>>
    ) -> Result<String> {
        let challenge = base64_url::encode(challenge);
        let request_body = json!({
            "challenge": challenge,
            "evidence": base64_url::encode(evidence),
            "policy_id": policy_id,
        });
        let mut map = HeaderMap::new();
        map.insert("Content-Type", HeaderValue::from_static("application/json"));
        let mut client = Self::create_client(self.access_as_protocol.clone(), 
            Some(self.cert_root.clone()), 
            true)?;

        if !self.as_client_sessions.session_map.is_empty() {
            let session = self.as_client_sessions
                .session_map
                .get_async(&challenge)
                .await;
            match session {
                Some(entry) => {
                    map.insert("as-challenge", HeaderValue::from_static("as"));
                    client = entry.get().as_client.clone()
                },
                None => log::info!("challenge is not as generate"),
            }
        }

        let attest_endpoint = format!("{}/attestation", self.config.svr_url);
        let res = client
            .post(attest_endpoint)
            .headers(map)
            .json(&request_body)
            .send()
            .await?;

        match res.status() {
            reqwest::StatusCode::OK => {
                let token = res.text().await?;
                log::debug!("Remote Attestation success, AS Response: {:?}", token);
                Ok(token)
            }
            _ => {
                bail!("Remote Attestation Failed, AS Response: {:?}", res.text().await?);
            }
        }
    }

    #[cfg(not(feature = "no_as"))]
    async fn token_to_teeclaim(&self, token: String) -> Result<TeeClaim> {
        let ret = self.verify_token(token).await;
        match ret {
            Ok(token) => {
                let token_claim: serde_json::Value = serde_json::from_slice(token.claim.as_bytes())?;
                Ok(token_claim as TeeClaim)
            },
            Err(e) => {
                log::error!("token to teeclaim failed:{:?}", e);
                Err(e)
            },
        }
    }

    async fn generate_challenge_local(&self) -> Result<String> {
        let mut nonce: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Ok(base64_url::encode(&nonce))
    }

    async fn get_challenge_from_as(&self) -> Result<String> {
        let challenge_endpoint = format!("{}/challenge", self.config.svr_url);
        let client = Self::create_client(self.access_as_protocol.clone(), 
            Some(self.cert_root.clone()), 
            true)?;
         
        let res = client
            .get(challenge_endpoint)
            .header("Content-Type", "application/json")
            .header("content-length", 0)
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
pub fn get_report(c_challenge: Option<&repr_c::Vec<u8>>, c_ima: &repr_c::TaggedOption<bool>) -> repr_c::Vec<u8> {
    log::debug!("input challenge: {:?}, ima: {:?}", c_challenge, c_ima);
    let ima = match c_ima {
        repr_c::TaggedOption::None => false,
        repr_c::TaggedOption::Some(ima) => *ima,
    };
    let challenge = match c_challenge {
        None => {log::error!("challenge is null"); return Vec::new().into();},
        Some(cha) => cha.clone().to_vec(),
    };

    let input: EvidenceRequest = EvidenceRequest {
        uuid: "f68fd704-6eb1-4d14-b218-722850eb3ef0".to_string(),
        challenge: challenge,
        ima: Some(ima),
    };
    let rt = Runtime::new().unwrap();
    let fut = async {
        AttestationAgent::new(Some(DEFAULT_AACONFIG_FILE.to_string())).unwrap().get_evidence(input).await
    };
    let ret = rt.block_on(fut);
    let report: Vec<u8> = match ret {
        Ok(report) => report,
        Err(e) => {
            log::error!("get report failed {:?}", e);
            Vec::new()
        },
    };

    report.into()
}

#[cfg(feature = "no_as")]
use verifier::virtcca_parse_evidence;

#[cfg(feature = "no_as")]
#[ffi_export]
pub fn parse_report(report: Option<&repr_c::Vec<u8>>) -> repr_c::String {
    let report = match report {
        None => {
            log::error!("report is null");
            return "".to_string().into();
        },
        Some(report) => report.clone().to_vec(),
    };
    let rt = Runtime::new().unwrap();
    let fut = async {virtcca_parse_evidence(&report)};
    let ret = rt.block_on(fut);
    
    let ret = match ret {
        Ok(claim) => {
            log::debug!("claim: {:?}", claim);
            claim.to_string()
        },
        Err(e) =>{
            log::error!("{e}");
            "".to_string()
        },
    };
    
    return ret.into();
}

#[ffi_export]
pub fn verify_report(c_challenge: Option<&repr_c::Vec<u8>>, report: Option<&repr_c::Vec<u8>>) -> repr_c::String {
    let challenge = match c_challenge {
        None => {
            log::error!("challenge is null");
            return "".to_string().into();
        },
        Some(cha) => cha.clone().to_vec(),
    };
    let report = match report {
        None => {
            log::error!("report is null");
            return "".to_string().into();
        },
        Some(report) => report.clone().to_vec(),
    };
    let rt = Runtime::new().unwrap();
    let fut = async {AttestationAgent::new(Some(DEFAULT_AACONFIG_FILE.to_string())).unwrap().verify_evidence(
            &challenge, &report, None).await};
    let ret = rt.block_on(fut);
    
    let ret = match ret {
        Ok(claim) => {
            log::debug!("claim: {:?}", claim);
            claim.to_string()
        },
        Err(e) =>{
            log::error!("{e}");
            "".to_string()
        },
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
