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
#![allow(clippy::redundant_field_names)]
#![allow(clippy::needless_return)]

pub mod restapi;
pub mod result;
pub mod session;

use actix_web::web::{self, Data};
use anyhow::{anyhow, Context, Result};
use attestation_types::resource::admin::simple::SimpleResourceAdmin;
use attestation_types::resource::admin::ResourceAdminInterface;
use attestation_types::resource::ResourceLocation;
use attestation_types::EvlResult;

use futures::lock::Mutex;
use policy::opa::OPA;
use policy::policy_engine::{PolicyEngine, PolicyEngineError};
use rand::RngCore;
use reference::reference::{RefOpError, ReferenceOps};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use session::SessionMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use token_signer::{EvlReport, TokenSignConfig, TokenSigner};
use verifier::{Verifier, VerifierAPIs};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ASConfig {
    pub token_cfg: TokenSignConfig,
    pub resource_policy: Option<PathBuf>,
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
    // Resource Administrator
    pub(crate) resource_admin: Arc<Mutex<dyn ResourceAdminInterface>>,
    // reference value provider sub service
    //rvps: ,
    // tee verifier sub service
    //verifier: ,
    // Sessions Map
    pub(crate) sessions: Data<SessionMap>,
}

impl Default for AttestationService {
    fn default() -> Self {
        Self {
            config: ASConfig::default(),
            resource_admin: Arc::new(Mutex::new(SimpleResourceAdmin::default())),
            sessions: web::Data::new(SessionMap::new()),
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
        Ok(AttestationService {
            config,
            resource_admin: Arc::new(Mutex::new(SimpleResourceAdmin::default())),
            sessions: web::Data::new(SessionMap::new()),
        })
    }

    async fn evaluate_evidence_field(claims_evidence: &Value, field: &str, passed: &mut bool) {
        log::debug!(
            "claims evidence {}: {:?}",
            field,
            claims_evidence[field].clone()
        );
        if *passed {
            match claims_evidence[field].clone() {
                Value::Object(obj) => {
                    for (_k, v) in obj {
                        if v == Value::Bool(false) {
                            *passed = false;
                            break;
                        }
                    }
                }
                _ => log::debug!("no {} result", field),
            }
        }
    }

    async fn evaluate_evidence_details(claims_evidence: &Value) -> bool {
        let mut passed = true;
        AttestationService::evaluate_evidence_field(claims_evidence, "ima", &mut passed).await;
        AttestationService::evaluate_evidence_field(claims_evidence, "uefi", &mut passed).await;
        AttestationService::evaluate_evidence_field(claims_evidence, "event", &mut passed).await;
        passed
    }

    /// evaluate tee evidence with reference and policy, and issue attestation result token
    pub async fn evaluate(
        &self,
        user_data: &[u8],
        evidence: &[u8],
        policy_ids: &Option<Vec<String>>,
    ) -> Result<String> {
        let verifier = Verifier::default();
        let claims_evidence = verifier.verify_evidence(user_data, evidence).await?;

        let passed = AttestationService::evaluate_evidence_details(&claims_evidence).await;

        // get reference by keys in claims_evidence
        let mut ops_refs = ReferenceOps::default();
        let refs_of_claims = ops_refs.query(&claims_evidence["payload"].to_string());
        log::debug!("refs_of_claims: {:?}", refs_of_claims);
        // apply policy to verify claims_evidence with reference value
        let policy_ids = match policy_ids {
            Some(policy_id) => policy_id.clone(),
            None => vec![],
        };
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let engine = OPA::new(&policy_dir).await.unwrap();
        let data = String::new();
        let tee_str = claims_evidence["tee"]
            .as_str()
            .ok_or(anyhow!("tee type unknown"))?;
        let tee_enum = attestation_types::TeeType::from_str(tee_str)
            .map_err(|e| anyhow!("invalid tee type: {}", e))?;

        let result = engine
            .evaluate(&tee_enum, &refs_of_claims.unwrap(), &data, &policy_ids)
            .await;
        let mut report = serde_json::json!({});
        let mut ref_verify: bool = true;

        match result {
            Ok(eval) => {
                log::debug!("policy: {:?}", eval);
                for id in eval.keys() {
                    let val = Value::from_str(&eval[id].clone())?;
                    let refs = match val
                        .as_object()
                        .ok_or(Err(anyhow!("json value to map fail")))
                    {
                        Err(err) => {
                            return Err(err.unwrap());
                        }
                        Ok(ret) => ret,
                    };
                    for key in refs.keys() {
                        // reference value is null means not found
                        if refs[key].is_null() || refs[key] == Value::Bool(false) {
                            ref_verify = false;
                        }
                    }
                    report
                        .as_object_mut()
                        .unwrap()
                        .insert(id.clone(), serde_json::Value::String(eval[id].clone()));
                }
            }
            Err(err) => {
                return Err(anyhow!("evaluate error: {err}"));
            }
        }

        // add ima detail result to report
        report
            .as_object_mut()
            .unwrap()
            .insert("ima".to_string(), claims_evidence["ima"].clone());

        // add event detail result to report
        report
            .as_object_mut()
            .unwrap()
            .insert("event".to_string(), claims_evidence["event"].clone());

        // add uefi detail result to report
        report
            .as_object_mut()
            .unwrap()
            .insert("uefi".to_string(), claims_evidence["uefi"].clone());

        // issue attestation result token
        let evl_report = EvlReport {
            tee: String::from(
                claims_evidence["tee"]
                    .as_str()
                    .ok_or(anyhow!("tee type unknown"))?,
            ),
            result: EvlResult {
                eval_result: passed & ref_verify,
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
        if let Some(mut ud) = user_data {
            nonce.append(&mut ud);
        }
        base64_url::encode(&nonce)
    }

    pub async fn set_policy(
        &self,
        id: &str,
        policy: &str,
        policy_dir: &String,
    ) -> Result<(), PolicyEngineError> {
        let engine = OPA::new(policy_dir).await;
        engine.unwrap().set_policy(id, policy).await
    }

    pub async fn get_all_policy(&self, policy_dir: &String) -> Result<String, PolicyEngineError> {
        let engine = OPA::new(policy_dir).await;
        match engine.unwrap().get_all_policy().await {
            Ok(map) => {
                let mut json_obj: serde_json::Value = serde_json::json!({});
                for key in map.keys() {
                    json_obj
                        .as_object_mut()
                        .unwrap()
                        .insert(key.clone(), serde_json::json!(map[key]));
                }
                Ok(json_obj.to_string())
            }
            Err(err) => Err(err),
        }
    }

    pub async fn get_policy(
        &self,
        policy_dir: &String,
        id: &str,
    ) -> Result<String, PolicyEngineError> {
        let engine = OPA::new(policy_dir).await?;
        engine.get_policy(id).await
    }

    pub async fn register_reference(&self, ref_set: &str) -> Result<(), RefOpError> {
        let mut ops_default = ReferenceOps::default();
        ops_default.register(ref_set)
    }

    pub async fn resource_evaluate(&self, resource: ResourceLocation, claim: &str) -> Result<bool> {
        self.resource_admin
            .lock()
            .await
            .evaluate_resource(resource, claim)
            .await
            .context("fail to evaluate resource according to the claim")
    }

    pub async fn get_resource(&self, location: ResourceLocation) -> Result<String> {
        let resource = self
            .resource_admin
            .lock()
            .await
            .get_resource(location)
            .await
            .context("fail to get resource")?;

        Ok(serde_json::to_string(&resource.get_content())?)
    }

    pub async fn list_resource(&self, vendor: &str) -> Result<Vec<ResourceLocation>> {
        self.resource_admin
            .lock()
            .await
            .list_resource(vendor)
            .await
            .context("faile to collect resource list in vendor")
    }

    pub fn get_sessions(&self) -> Data<SessionMap> {
        self.sessions.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::AttestationService;
    use serde_json::json;

    #[tokio::test]
    async fn evidence_detail_results_fail_when_uefi_reference_mismatches() {
        let claims_evidence = json!({
            "ima": {},
            "uefi": {
                "kernel": false
            },
            "event": {}
        });

        assert!(!AttestationService::evaluate_evidence_details(&claims_evidence).await);
    }
}
