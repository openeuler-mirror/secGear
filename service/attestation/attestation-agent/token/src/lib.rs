use anyhow::{Result, bail};
use std::path::Path;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation };
use token_signer::Claims;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenVerifyConfig {
    pub cert: String,       // Attestation Service cert to verify jwt token signature
    pub iss: String,        // Attestation Service name
    //pub root_cert: String,
}

impl Default for TokenVerifyConfig {
    fn default() -> Self {
        TokenVerifyConfig {
            cert: "/etc/attestation/attestation-agent/as_cert.pem".to_string(),
            iss: "openEulerAS".to_string(),
        }
    }
}
pub struct TokenVerifier
{
    pub config: TokenVerifyConfig,
}

impl Default for TokenVerifier
{
    fn default() -> Self {
        TokenVerifier {
            config: TokenVerifyConfig::default(),
        }
    }
}

// 返回token的原始数据
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct TokenRawData {
    pub header: String,
    pub claim: String,
}

impl TokenVerifier {
    pub fn new(config: TokenVerifyConfig) -> Result<Self> {
        Ok(TokenVerifier { config })
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
    pub fn verify(
        &self,
        token: &String
    ) -> Result<TokenRawData> {
        let header = match decode_header(&token) {
            Ok(h) => h,
            Err(e) => bail!("decode jwt header error {:?}", e),
        };
        let alg: Algorithm = header.alg;

        if !Self::support_rs(&alg) && !Self::support_ps(&alg) {
            bail!("unknown algrithm {:?}", alg);
        }
        if !Path::new(&self.config.cert).exists() {
            bail!("token verfify failed, {:?} cert not exist", self.config.cert);
        }
        let cert = std::fs::read(&self.config.cert).unwrap();

        /* 使用配置的公钥 */
        let key_value: DecodingKey = match DecodingKey::from_rsa_pem(&cert)
        {
            Ok(key) => key,
            Err(e) => bail!("get key from pem error {:?}", e),
        };

        let mut validation = Validation::new(alg);
        validation.set_issuer(&[self.config.iss.clone()]);
        validation.validate_exp = true;

        let data = decode::<Claims>(&token, &key_value, &validation);
        match data {
            Ok(d) => {
                let header = d.header.clone();
                let claims = d.claims.clone();
                Ok(TokenRawData {
                    header: serde_json::to_string(&header).unwrap(),
                    claim: serde_json::to_string(&claims).unwrap(),
                })
            }
            Err(e) => bail!("verfiy jwt failed {:?}", e),
        }
    }
}
