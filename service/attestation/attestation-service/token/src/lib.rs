use anyhow::{Result, bail};
use jsonwebtoken::{encode, get_current_timestamp,
    Algorithm, EncodingKey, Header,
};
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    iss: String,
    iat: usize,
    nbf: usize,
    exp: usize,
    evaluation_reports: EvlResult,
    tee: TeeType,
    tcb_status: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSignConfig {
    pub iss: String,
    pub nbf: usize,            // 生效时刻
    pub valid_duration: usize, // 有效时间
    pub alg: SignAlg,
    pub key: String,
}

impl Default for TokenSignConfig {
    fn default() -> Self {
        TokenSignConfig {
            iss: "openEulerAS".to_string(),
            nbf: 0,
            valid_duration: 300,
            alg: SignAlg::PS256,
            key: "/etc/attestation/attestation-service/token/private.pem".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvlResult {
    pub policy: Vec<String>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TeeType {
    KUNPENG(String),
    VIRTCCA(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvlReport {
    pub tee: TeeType,
    pub result: EvlResult,
    pub tcb_status: Value,
}

pub type SignAlg = Algorithm;
pub struct TokenSigner {
    pub config: TokenSignConfig,
}

impl Default for TokenSigner {
    fn default() -> Self {
        TokenSigner {
            config: TokenSignConfig::default(),
        }
    }
}

impl TokenSigner {
    pub fn new(config: TokenSignConfig) -> Result<Self> {
        Ok(TokenSigner { config })
    }
    fn support_rs(alg: &Algorithm) -> bool
    {
        if *alg == Algorithm::RS256 || *alg == Algorithm::RS384 || *alg == Algorithm::RS512{
            return true;
        }
        return false;
    }
    fn support_ps(alg: &Algorithm) -> bool
    {
        if *alg == Algorithm::PS256 || *alg == Algorithm::PS384 || *alg == Algorithm::PS512 {
            return true;
        }
        return false;
    }
    pub fn sign(&self, report: &EvlReport) -> Result<String> {
        let alg: Algorithm = self.config.alg;
        let mut header = Header::new(alg);
        header.typ = Some("JWT".to_string());
        let unix_time = get_current_timestamp();
        let claims: Claims = Claims {
            iss: self.config.iss.clone(),
            iat: usize::try_from(unix_time).expect("unix time to usize error"),
            nbf: usize::try_from(unix_time).expect("unix time to usize error"),
            exp: usize::try_from(unix_time).expect("unix time to usize error")
                + self.config.valid_duration,
            evaluation_reports: report.result.clone(),
            tee: report.tee.clone(),
            tcb_status: report.tcb_status.clone(),
        };
        if !Self::support_rs(&alg) && !Self::support_ps(&alg) {
            bail!("unknown algrithm {:?}", alg);
        }
        if !Path::new(&self.config.key).exists() {
            bail!("token verfify failed, {:?} cert not exist", self.config.key);
        }
        let key = std::fs::read(&self.config.key).unwrap();
        let key_value: EncodingKey = match EncodingKey::from_rsa_pem(&key) {
            Ok(val) => val,
            _ => bail!("get key from input error"),
        };
        
        let token = match encode(&header, &claims, &key_value) {
            Ok(val) => val,
            Err(e) => bail!("sign jwt token error {:?}", e),
        };
        Ok(token)
    }
}