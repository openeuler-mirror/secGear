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
use anyhow::{Result, anyhow};
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use rand::RngCore;
use base64_url;

use verifier::{Verifier, VerifierAPIs};
use token_signer::{EvlReport, TokenSigner, TokenSignConfig};
use reference::reference::{ReferenceOps, RefOpError};
use policy::opa::OPA;
use policy::policy_engine::{PolicyEngine, PolicyEngineError};
use attestation_types::EvlResult;

pub mod result;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ASConfig {
    pub token_cfg: TokenSignConfig,
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
    pub config: ASConfig,
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
        policy_ids: &Option<Vec<String>>
    ) -> Result<String> {
        let verifier = Verifier::default();
        let claims_evidence = verifier.verify_evidence(user_data, evidence).await?;

        let mut passed = true;
        log::debug!("claims evidece ima: {:?}", claims_evidence["ima"].clone());
        match claims_evidence["ima"].clone() {
            serde_json::Value::Object(obj) => {
                for (_k, v) in obj {
                    if v == Value::Bool(false) {
                        passed = false;
                        break;
                    }
                }
            }
            _ => log::debug!("no ima result"),
        }

        // get reference by keys in claims_evidence
        let mut ops_refs = ReferenceOps::default();
        let refs_of_claims = ops_refs.query(&claims_evidence["payload"].to_string());
        // apply policy to verify claims_evidence with reference value
        let policy_ids = match policy_ids {
            Some(policy_id) => policy_id.clone(),
            None => vec![],
        };
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let engine = OPA::new(&policy_dir).await.unwrap();
        let data = String::new();
        let result = engine.evaluate(&String::from(claims_evidence["tee"]
            .as_str().ok_or(anyhow!("tee type unknown"))?),
    &refs_of_claims.unwrap(), &data, &policy_ids).await;
        let mut report = serde_json::json!({});
        let mut ref_exist_null: bool = false;
        match result {
            Ok(eval) => {
                for id in eval.keys() {
                    let val = Value::from_str(&eval[id].clone())?;
                    let refs = match val.as_object().ok_or(Err(anyhow!("json value to map fail"))) {
                        Err(err) => { return Err(err.unwrap()); }
                        Ok(ret) => { ret }
                    };
                    for key in refs.keys() {
                        // reference value is null means not found
                        if refs[key].is_null() {
                            ref_exist_null = true;
                        }  
                    }
                    report.as_object_mut().unwrap().insert(id.clone(), serde_json::Value::String(eval[id].clone()));
                }
            }
            Err(err) => {
                return Err(anyhow!("evaluate error: {err}"));
            }
        }
        
        // add ima detail result to report
        report.as_object_mut().unwrap().insert("ima".to_string(), claims_evidence["ima"].clone());

        // issue attestation result token
        let evl_report = EvlReport {
            tee: String::from(claims_evidence["tee"].as_str().ok_or(anyhow!("tee type unknown"))?),
            result: EvlResult {
                eval_result: passed & !ref_exist_null,
                policy: policy_ids,
                report: report,
            },
            tcb_status: claims_evidence["payload"].clone(),
        };
        // demo get signer, todo default signer
        let signer = TokenSigner::new(self.config.token_cfg.clone())?;

        Ok(signer.sign(&evl_report)?)
    }

    pub async fn generate_challenge(&self, user_data: Option<Vec<u8>>) -> String {
        let mut nonce: Vec<u8> = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        if user_data != None {
            nonce.append(&mut user_data.unwrap());
        }
        base64_url::encode(&nonce)
    }

    pub async fn set_policy(&self,
        id: &String,
        policy: &String,
        policy_dir: &String,
    ) -> Result<(), PolicyEngineError> {
        let engine = OPA::new(policy_dir).await;
        engine.unwrap()
            .set_policy(id, policy)
            .await
    }

    pub async fn get_all_policy(&self,
        policy_dir: &String,
    ) -> Result<String, PolicyEngineError> {
        let engine = OPA::new(policy_dir).await;
        match engine.unwrap().get_all_policy().await {
            Ok(map) => {
                let mut json_obj: serde_json::Value = serde_json::json!({});
                for key in map.keys() {
                    json_obj.as_object_mut()
                    .unwrap()
                    .insert(key.clone(), serde_json::json!(map[key]));
                }
                Ok(json_obj.to_string())
            }
            Err(err) => Err(err)
        }
    }

    pub async fn get_policy(&self,
        policy_dir: &String,
        id: &String 
    ) -> Result<String, PolicyEngineError> {
        let engine = OPA::new(policy_dir).await?;
        Ok(engine.get_policy(id).await?)
    }

    pub async fn register_reference(&self,
        ref_set: &String
    ) -> Result<(), RefOpError> {
        let mut ops_default = ReferenceOps::default();
        ops_default.register(ref_set)
    }
}
