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
use anyhow::Result;
use attestation_types::{Claims, EvlResult};
use jsonwebtoken::{
    decode, decode_header, encode, get_current_timestamp, Algorithm, DecodingKey, EncodingKey,
    Header, Validation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror;

const PRIVATE_KEY_PATH: &str = "/etc/attestation/attestation-service/token/private.pem";

#[derive(thiserror::Error, Debug)]
pub enum SignError {
    #[error("get unix time fail:{0:?}")]
    ToUnixTimeFail(#[from] std::num::TryFromIntError),
    #[error("unsupport algorith:{0}")]
    UnsupportAlg(String),
    #[error("key not exist:{0}")]
    KeyNotExist(String),
    #[error("key content read fail:{0}")]
    ReadKeyFail(String),
    #[error("sign fail:{0:?}")]
    SignFail(#[from] jsonwebtoken::errors::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSignConfig {
    pub iss: String,
    pub nbf: usize,            // 生效时刻
    pub valid_duration: usize, // 有效时间
    pub alg: SignAlg,
    pub key: Vec<u8>,
}

impl Default for TokenSignConfig {
    fn default() -> Self {
        let default_key = std::fs::read(PRIVATE_KEY_PATH)
        .map_err(|err| {
            SignError::ReadKeyFail(format!("Failed to read {PRIVATE_KEY_PATH}: {err}"))
        })
        .unwrap();

        TokenSignConfig {
            iss: "oeas".to_string(),
            nbf: 0,
            valid_duration: 300,
            alg: SignAlg::PS256,
            key: default_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvlReport {
    pub tee: String,
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
    fn support_rs(alg: &Algorithm) -> bool {
        if *alg == Algorithm::RS256 || *alg == Algorithm::RS384 || *alg == Algorithm::RS512 {
            return true;
        }
        return false;
    }
    fn support_ps(alg: &Algorithm) -> bool {
        if *alg == Algorithm::PS256 || *alg == Algorithm::PS384 || *alg == Algorithm::PS512 {
            return true;
        }
        return false;
    }
    pub fn sign(&self, report: &EvlReport) -> Result<String, SignError> {
        let alg: Algorithm = self.config.alg;
        let mut header = Header::new(alg);
        header.typ = Some("JWT".to_string());
        let unix_time = get_current_timestamp();
        let claims: Claims = Claims {
            iss: self.config.iss.clone(),
            iat: usize::try_from(unix_time)?,
            nbf: usize::try_from(unix_time)?,
            exp: usize::try_from(unix_time)? + self.config.valid_duration,
            evaluation_reports: report.result.clone(),
            tee: report.tee.clone(),
            tcb_status: report.tcb_status.clone(),
        };
        if !Self::support_rs(&alg) && !Self::support_ps(&alg) {
            return Err(SignError::UnsupportAlg(format!(
                "unknown algrithm {:?}",
                alg
            )));
        }

        let key_value: EncodingKey = match EncodingKey::from_rsa_pem(&self.config.key) {
            Ok(val) => val,
            _ => {
                return Err(SignError::ReadKeyFail(format!("get key from input error")));
            }
        };

        let token = match encode(&header, &claims, &key_value) {
            Ok(val) => val,
            Err(e) => {
                return Err(SignError::SignFail(e));
            }
        };
        Ok(token)
    }
}

pub fn verify(token: &String) -> Result<Claims> {
    let header = decode_header(&token)?;
    let alg: Algorithm = header.alg;

    // todo: check support of verification algorithm

    let cert = std::fs::read("/etc/attestation/attestation-service/token/as_cert.pem").unwrap();
    let key_value = DecodingKey::from_rsa_pem(&cert)?;
    let validation = Validation::new(alg);

    let data = decode::<Claims>(&token, &key_value, &validation)?;
    Ok(data.claims)
}
