use anyhow::{Result, anyhow};
use std::fs::File;
use std::path::Path;
use serde::{Serialize, Deserialize};

use verifier::{Verifier, VerifierAPIs};
use token::{EvlReport, EvlResult, TokenSigner, TokenSignConfig};



pub mod result;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ASConfig {
    token_cfg: TokenSignConfig,
}

impl Default for ASConfig {
    fn default() -> Self {
        Self {
            token_cfg: TokenSignConfig::default(),
        }
    }
}

impl TryFrom<&Path> for ASConfig {
    /// Load `ASConfig` from a configuration file like:
    ///    {
    ///         "token_cfg": {
    ///             "key": "/etc/attestation/attestation-service/token/private.pem",
    ///             "iss": "oeas",
    ///             "nbf": 0,
    ///             "valid_duration": 300,
    ///             "alg": "PS256"
    ///         }
    ///    }

    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path)?;
        serde_json::from_reader::<File, ASConfig>(file).map_err(|e| anyhow!("invalid asconfig {e}"))
    }
}

pub struct AttestationService {
    config: ASConfig,
    // verify policy sub service
    //policy: ,
    // reference value provider sub service
    //rvps: ,
    // tee verifier sub service
    //verifier: ,
}

impl Default for AttestationService {
    fn default() -> Self {
        Self {
            config: ASConfig::default(),
        }
    }
}

impl AttestationService {
    pub fn new(conf_path: Option<String>) -> Result<Self> {
        let config = match conf_path {
            Some(conf_path) => {
                log::info!("Attestation Service config file:{conf_path}");
                ASConfig::try_from(Path::new(&conf_path))?
            }
            None => {
                log::warn!("No Attestation Agent config file specified. Using a default config");
                ASConfig::default()
            }
        };
        Ok(AttestationService {config})
    }
    /// evaluate tee evidence with reference and policy, and issue attestation result token
    pub async fn evaluate(
        &self,
        user_data: &[u8],
        evidence: &[u8],
    ) -> Result<String> {
        let verifier = Verifier::default();
        let claims_evidence = verifier.verify_evidence(user_data, evidence).await?;

        // get reference by keys in claims_evidence

        // apply policy to verify claims_evidence with reference value

        // issue attestation result token
        let evl_report = EvlReport {
            tee: token::TeeType::KUNPENG(claims_evidence["tee_type"].to_string()),
            result: EvlResult {
                policy: vec![String::from("default")],
                passed: true,
            },
            tcb_status: claims_evidence["payload"].clone(),
        };
        // demo get signer, todo default signer
        let signer = TokenSigner::new(self.config.token_cfg.clone())?;

        signer.sign(&evl_report)
    }

    // todo pub fun set policy

    // todo pub fun get policy

    // todo pub fun import reference value
}
