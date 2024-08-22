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
use serde::{Serialize, Deserialize};
use async_trait::async_trait;
use std::fs::File;
use std::path::Path;
use rand::RngCore;

use attester::{Attester, AttesterAPIs};
use token_verifier::{TokenVerifyConfig, TokenVerifier, TokenRawData};

pub mod result;
use result::Error;
pub type TeeClaim = serde_json::Value;

#[cfg(feature = "no_as")]
use verifier::{Verifier, VerifierAPIs};

#[cfg(not(feature = "no_as"))]
use {serde_json::json, reqwest, base64_url};

pub use attester::EvidenceRequest;

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
            return Ok("no as in not supprot get token".to_string());
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
        let result = verifier.verify(&token);
        match result {
            Ok(raw_token) => Ok(raw_token as AsTokenClaim),
            Err(e) => bail!("verify token failed {:?}", e),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AAConfig {
    svr_url: String,             // Attestation Service url
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
    config: AAConfig,
    client: reqwest::Client,
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
        let client = reqwest::ClientBuilder::new()
        .cookie_store(true)
        .user_agent("attestation-agent-client")
        .build()
        .map_err(|e| result::Error::AttestationAgentError(format!("build http client {e}")))?;
        Ok(AttestationAgent {
            config,
            client,
        })
    }

    #[cfg(not(feature = "no_as"))]
    async fn verify_evidence_by_as(&self,
        challenge: &[u8],
        evidence: &[u8],
        policy_id: Option<Vec<String>>
    ) -> Result<String> {
        let request_body = json!({
            "challenge": base64_url::encode(challenge),
            "evidence": base64_url::encode(evidence),
            "policy_id": policy_id,
        });

        let attest_endpoint = format!("{}/attestation", self.config.svr_url);
        let res = self.client
            .post(attest_endpoint)
            .header("Content-Type", "application/json")
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
                let tee_claim = json!({
                    "tee": token_claim["tee"].clone(),
                    "payload" : token_claim["tcb_status"].clone(),
                });
                Ok(tee_claim as TeeClaim)
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
        let res = self.client
            .get(challenge_endpoint)
            .header("Content-Type", "application/json")
            .header("content-length", 0)
            //.json(&request_body)
            .send()
            .await?;
        let challenge = match res.status() {
            reqwest::StatusCode::OK => {
                let respone = res.json().await.unwrap();
                log::info!("get challenge success, AS Response: {:?}", respone);
                respone
            }
            status => {
                log::info!("get challenge Failed, AS Response: {:?}", status);
                bail!("get challenge Failed")
            }
        };
        Ok(challenge)
    }
}


// attestation agent c interface
use safer_ffi::prelude::*;
use futures::executor::block_on;
use tokio::runtime::Runtime;

#[ffi_export]
pub fn get_report(c_challenge: Option<&repr_c::Vec<u8>>, c_ima: &repr_c::TaggedOption<bool>) -> repr_c::Vec<u8> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
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

    let fut = async {
        AttestationAgent::new(Some(DEFAULT_AACONFIG_FILE.to_string())).unwrap().get_evidence(input).await
    };
    let report: Vec<u8> = match block_on(fut) {
        Ok(report) => report,
        Err(e) => {
            log::error!("get report failed {:?}", e);
            Vec::new()
        },
    };

    report.into()
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


#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn aa_new_no_conf_path() {
        let aa = AttestationAgent::new(None).unwrap();
        assert_eq!(aa.config.svr_url, "http://127.0.0.1:8080");
        assert_eq!(aa.config.token_cfg.cert, "/etc/attestation/attestation-agent/as_cert.pem");
        assert_eq!(aa.config.token_cfg.iss, "openEulerAS");
    }

    #[test]
    fn aa_new_with_example_conf() {
        let aa = AttestationAgent::new(Some("attestation-agent.conf".to_string())).unwrap();
        assert_eq!(aa.config.token_cfg.cert, "/home/cert/as_cert.pem");
        assert_eq!(aa.config.token_cfg.iss, "oeas");
    }
}
