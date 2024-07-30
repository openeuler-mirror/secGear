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

use attester::{Attester, AttesterAPIs};
use token::{TokenVerifyConfig, TokenVerifier, TokenRawData};

pub mod result;
pub type TeeClaim = serde_json::Value;

#[cfg(feature = "no_as")]
use verifier::{Verifier, VerifierAPIs};

#[cfg(not(feature = "no_as"))]
use {serde_json::json, reqwest, base64_url};

pub use attester::EvidenceRequest;

pub type AsTokenClaim = TokenRawData;

#[async_trait]
pub trait AttestationAgentAPIs {
    /// `get_evidence`: get hardware TEE signed evidence due to given user_data,
    /// such as input random challenge to prevent replay attacks
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>>;

    /// `verify_evidence`: verify the integrity of TEE evidence and evaluate the
    /// claims against the supplied reference values
    async fn verify_evidence(&self, challenge: &[u8], evidence: &[u8]) -> Result<()>;

    #[cfg(not(feature = "no_as"))]
    async fn get_token(&self, user_data: EvidenceRequest) -> Result<String>;

    async fn verify_token(&self, token: String) -> Result<AsTokenClaim>;
}

#[async_trait]
impl AttestationAgentAPIs for AttestationAgent {
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>> {
        Attester::default().tee_get_evidence(user_data).await
    }
    async fn verify_evidence(&self, challenge: &[u8], evidence: &[u8]) -> Result<()> {
        #[cfg(feature = "no_as")]
        {
            let ret = Verifier::default().verify_evidence(challenge, evidence).await;
            match ret {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        }

        #[cfg(not(feature = "no_as"))]
        {
            let ret = self.request_as(challenge, evidence).await;
            match ret {
                Ok(_) => Ok(()),
                Err(e) => bail!("verify evidence failed {:?}", e),
            }
        }
    }
    #[cfg(not(feature = "no_as"))]
    async fn get_token(&self, user_data: EvidenceRequest) -> Result<String> {
        // todo token 有效期内，不再重新获取报告
        let evidence = self.get_evidence(user_data.clone()).await?;
        let challenge = &user_data.challenge;
        // request as
        return self.request_as(challenge, &evidence).await;
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
}

impl Default for AttestationAgent {
    fn default() -> Self {
        AttestationAgent {
            config: AAConfig::default(),
        }
    }
}

#[allow(dead_code)]
impl AttestationAgent {
    pub fn new(conf_path: Option<String>) -> Result<Self> {
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
        Ok(AttestationAgent {config})
    }

    #[cfg(not(feature = "no_as"))]
    async fn request_as(&self, challenge: &[u8], evidence: &[u8]) -> Result<String> {
        let request_body = json!({
            "challenge": base64_url::encode(challenge),
            "evidence": base64_url::encode(evidence),
        });

        let client = reqwest::Client::new();
        let attest_endpoint = format!("{}/attestation", self.config.svr_url);
        let res = client
            .post(attest_endpoint)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        match res.status() {
            reqwest::StatusCode::OK => {
                let token = res.text().await?;
                println!("Remote Attestation success, AS Response: {:?}", token);
                Ok(token)
            }
            _ => {
                bail!(
                    "Remote Attestation Failed, AS Response: {:?}",
                    res.text().await?
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn aa_default_conf_file() {
        let aa = AttestationAgent::default();
        assert_eq!(aa.config.svr_url, "http://127.0.0.1:8080");
        assert_eq!(aa.config.token_cfg.cert, "/etc/attestation/attestation-agent/as_cert.pem");
        assert_eq!(aa.config.token_cfg.iss, "openEulerAS");
    }

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
