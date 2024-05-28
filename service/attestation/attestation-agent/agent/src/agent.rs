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

use anyhow::Result;
use log;
use serde::{Serialize, Deserialize};
use async_trait::async_trait;

use attester::{Attester, AttesterAPIs};

#[cfg(feature = "no_as")]
use verifier::{Verifier, VerifierAPIs};

const DEFAULT_AA_CONF_PATH: &str = "/etc/attestation/attestation-agent.toml";

pub use attester::EvidenceRequest;

#[async_trait]
pub trait AttestationAgentAPIs {
    /// `get_evidence`: get hardware TEE signed evidence due to given user_data,
    /// such as input random challenge to prevent replay attacks
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>>;

    /// `verify_evidence`: verify the integrity of TEE evidence and evaluate the
    /// claims against the supplied reference values
    async fn verify_evidence(&self, challenge: &[u8], evidence: &[u8]) -> Result<()>;
}

#[async_trait]
impl AttestationAgentAPIs for AttestationAgent {
    async fn get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>> {
        Attester::default().tee_get_evidence(user_data).await
    }
    async fn verify_evidence(&self, challenge: &[u8], evidence: &[u8]) -> Result<()> {
        #[cfg(feature = "no_as")]
        let _ret = Verifier::default().verify_evidence(challenge, evidence).await?;

        let _ret = request_as(challenge, evidence);
        return _ret;
    }
}

fn request_as(challenge: &[u8], evidence: &[u8]) -> Result<()> {
    let _ = challenge;
    let _ = evidence;
    // todo send request to attestation service
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AAConfig {
    svr_url: String,                // Attestation Service url
}

impl Default for AAConfig {
    fn default() -> Self {
        Self {
            svr_url: String::from(""),
        }
    }
}

impl TryFrom<&str> for AAConfig {
    type Error = config::ConfigError;
    fn try_from(config_path: &str) -> Result<Self, Self::Error> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()?;
        let cfg = c.try_deserialize()?;
        Ok(cfg)
    }
}

#[derive(Debug)]
pub struct AttestationAgent {
    _config: AAConfig,
}

impl Default for AttestationAgent {
    fn default() -> Self {
        if let Ok(_config) = AAConfig::try_from(DEFAULT_AA_CONF_PATH) {
            log::info!("attestation agent construct with default config file");
            return AttestationAgent { _config };
        }
        log::warn!("The default conf file {} is missing", DEFAULT_AA_CONF_PATH);
        Self {
            _config: AAConfig::default(),
        }
    }
}

#[allow(dead_code)]
impl AttestationAgent {
    pub fn new(conf_path: Option<&str>) -> Result<Self> {
        let _config = match conf_path {
            Some(conf_path) => {
                log::info!("Attestation Agent config file:{conf_path}");
                AAConfig::try_from(conf_path)?
            }
            None => {
                log::warn!("No Attestation Agent config file specified. Using a default config");
                AAConfig::default()
            }
        };
        Ok(AttestationAgent {_config})
    }
}

#[cfg(test)]
mod tests {
    use crate::agent::*;

    #[test]
    fn aa_default_conf_file() {
        let aa = AttestationAgent::default();
        assert_eq!(aa._config.svr_url, "http://127.0.0.1:8000");
    }

    #[test]
    fn aa_new_no_conf_path() {
        let aa = AttestationAgent::new(None).unwrap();
        assert_eq!(aa._config.svr_url, "");
    }

    #[test]
    fn aa_new_with_example_conf() {
        let aa = AttestationAgent::new(Some("attestation-agent.example.toml")).unwrap();
        assert_eq!(aa._config.svr_url, "http://127.0.0.1:8888");
    }
}
