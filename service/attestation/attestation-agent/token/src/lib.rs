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
use std::path::Path;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation };
use attestation_types::Claims;

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("parse fail:{0:?}")]
    CommError(#[from] jsonwebtoken::errors::Error),
    #[error("unknown algorithm:{0}")]
    UnknownAlg(String),
    #[error("certificate not exist:{0}")]
    CertNotExist(String),
    #[error("serialize fail:{0}")]
    SerializeFail(#[from] serde_json::error::Error),
}

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
            iss: "oeas".to_string(),
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
    pub fn new(config: TokenVerifyConfig) -> Result<Self, VerifyError> {
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
    ) -> Result<TokenRawData, VerifyError> {
        let header = decode_header(&token)?;
        let alg: Algorithm = header.alg;

        if !Self::support_rs(&alg) && !Self::support_ps(&alg) {
            return Err(VerifyError::UnknownAlg(format!("unknown algrithm {:?}", alg)));
        }
        if !Path::new(&self.config.cert).exists() {
            return Err(VerifyError::CertNotExist(format!("{:?} not exist", self.config.cert)));
        }
        let cert = std::fs::read(&self.config.cert).unwrap();

        /* 使用配置的公钥 */
        let key_value: DecodingKey = DecodingKey::from_rsa_pem(&cert)?;

        let mut validation = Validation::new(alg);
        validation.set_issuer(&[self.config.iss.clone()]);
        validation.validate_exp = true;

        let data = decode::<Claims>(&token, &key_value, &validation)?;
        Ok(TokenRawData {
            header: serde_json::to_string(&data.header)?,
            claim: serde_json::to_string(&data.claims)?,
        })
    }
}
