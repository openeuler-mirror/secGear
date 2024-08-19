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
use serde::{Serialize, Deserialize};
use rand::RngCore;
use base64_url;

use verifier::{Verifier, VerifierAPIs, virtcca::ima::ImaVerify};
use token_signer::{EvlReport, EvlResult, TokenSigner, TokenSignConfig};
use reference::reference::{ReferenceOps, RefOpError};
use policy::opa::OPA;
use policy::policy_engine::{PolicyEngine, PolicyEngineError};

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

        let mut passed = false;
        let ima_result = ImaVerify::default().ima_verify(evidence, &claims_evidence, "/etc/attestation/attestation-service/verifier/digest_list_file".to_string());
        if ima_result.is_ok() {
            passed = true;
        }
        // get reference by keys in claims_evidence
        let mut ops_refs = ReferenceOps::default();
        let refs_of_claims = ops_refs.query(&claims_evidence.to_string());
        // apply policy to verify claims_evidence with reference value
        let policy_ids = match policy_ids {
            Some(polciy_id) => polciy_id.clone(),
            None => vec![],
        };
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let engine = OPA::new(&policy_dir).await.unwrap();
        let data = String::new();
        let result = engine.evaluate(&refs_of_claims.unwrap(), &data, &policy_ids).await;
        let mut report = serde_json::json!({});
        match result {
            Ok(eval) => {
                for id in eval.keys() {
                    report.as_object_mut().unwrap().insert(id.clone(), serde_json::Value::String(eval[id].clone()));
                }
            }
            Err(err) => {
                return Err(anyhow!("evaluate error: {err}"));
            }
        }
        
        // issue attestation result token
        let evl_report = EvlReport {
            tee: claims_evidence["tee"].to_string(),
            result: EvlResult {
                eval_reulst: passed,
                policy: policy_ids,
                report: report,
            },
            tcb_status: claims_evidence["payload"].clone(),
        };
        // demo get signer, todo default signer
        let signer = TokenSigner::new(self.config.token_cfg.clone())?;

        signer.sign(&evl_report)
    }

    pub async fn generate_challenge(&self) -> String {
        let mut nonce: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        base64_url::encode(&nonce)
    }

    // todo pub fun set policy
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
    // todo pub fun get policy
    pub async fn get_policy(&self,
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
    // todo pub fun import reference value
    pub async fn register_reference(&self,
        ref_set: &String
    ) -> Result<(), RefOpError> {
        let mut ops_default = ReferenceOps::default();
        ops_default.register(ref_set)
    }
}
