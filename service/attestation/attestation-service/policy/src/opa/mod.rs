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
use base64::Engine;
use policy_engine::{PolicyEngine, PolicyEngineError};
use regorus::Value;
use std::{collections::HashMap, path::PathBuf};

use crate::policy_engine;

#[derive(Debug, Clone, PartialEq)]
pub struct OPA {
    policy_dir: PathBuf,
    default_policy_dir: PathBuf,
    default_policy_vcca: String,
    default_policy_itrustee: String,
}

const DEFAULT_POLICY_DIR: &str = "/etc/attestation/attestation-service/policy/";
const DEFAULT_VCCA_REGO: &str = "default_vcca.rego";
const DEFAULT_ITRUSTEE_REGO: &str = "default_itrustee.rego";

impl PolicyEngine for OPA {
    /// refs comes from report, by using query reference API
    async fn evaluate(
        &self,
        tee: &String,
        refs: &String,
        data_for_policy: &String,
        policy_id: &Vec<String>,
    ) -> Result<HashMap<String, String>, PolicyEngineError> {
        let mut policy_id_used = policy_id.clone();
        let policy_path: PathBuf;
        if policy_id_used.is_empty() {
            if tee == "vcca" {
                policy_id_used.push(String::from(DEFAULT_VCCA_REGO));
            } else if tee == "itrustee" {
                policy_id_used.push(String::from(DEFAULT_ITRUSTEE_REGO));
            } else {
                return Err(PolicyEngineError::TeeTypeUnknown(format!("tee type unknown: {tee}")));
            }
            policy_path = self.default_policy_dir.clone();
        } else {
            policy_path = self.policy_dir.clone();
        }

        let mut result: HashMap<String, String> = HashMap::new();
        for id in policy_id_used {
            let mut path = policy_path.clone();
            path.push(id.clone());
            let engine_policy = tokio::fs::read_to_string(path.clone()).await.map_err(|err| {
                PolicyEngineError::ReadPolicyError(format!("read policy failed: {}", err))
            })?;
            let mut engine = regorus::Engine::new();
            engine.add_policy(id.clone(), engine_policy).map_err(|err| {
                PolicyEngineError::EngineLoadPolicyError(format!("policy load failed: {}", err))
            })?;

            let input = Value::from_json_str(refs).map_err(|err| {
                PolicyEngineError::InvalidReport(format!("report to Value failed: {}", err))
            })?;
            engine.set_input(input);

            if !data_for_policy.is_empty() {
                let data = Value::from_json_str(data_for_policy).map_err(|err| {
                    PolicyEngineError::EngineLoadDataError(format!("data to Value failed: {}", err))
                })?;
                engine.add_data(data).map_err(|err| {
                    PolicyEngineError::EngineLoadDataError(format!("engine add data failed: {}", err))
                })?;
            }

            let eval = engine
                .eval_rule(String::from("data.attestation.output"))
                .map_err(|err| {
                    PolicyEngineError::EngineEvalError(format!("engine eval error:{}", err))
                })?;
            result.insert(id, eval.to_string());
        }
        Ok(result)
    }
    async fn set_policy(
        &self,
        policy_id: &String,
        policy: &String,
    ) -> Result<(), PolicyEngineError> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(policy)
            .map_err(|err| PolicyEngineError::InvalidPolicy(format!("policy decode failed: {}", err)))?;

        let mut policy_file: PathBuf = self.policy_dir.clone();
        policy_file.push(format!("{}", policy_id));
        tokio::fs::write(policy_file.as_path(), &raw)
            .await
            .map_err(|err| PolicyEngineError::WritePolicyError(format!("write policy failed: {}", err)))?;
        Ok(())
    }

    async fn get_all_policy(&self) -> Result<HashMap<String, String>, PolicyEngineError> {
        let mut items = tokio::fs::read_dir(&self.policy_dir.as_path())
            .await
            .map_err(|err| PolicyEngineError::ReadPolicyError(format!("read policy failed: {}", err)))?;
        let mut policies = HashMap::new();
        while let Some(item) = items
            .next_entry()
            .await
            .map_err(|err| PolicyEngineError::ReadPolicyError(format!("read policy failed: {}", err)))?
        {
            let path = item.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rego") {
                let content: String =
                    tokio::fs::read_to_string(path.clone()).await.map_err(|err| {
                        PolicyEngineError::ReadPolicyError(format!("read policy failed: {}", err))
                    })?;
                let name = path
                    .file_stem()
                    .ok_or(PolicyEngineError::ReadPolicyError(
                        "get policy name failed".to_string(),
                    ))?
                    .to_str()
                    .ok_or(PolicyEngineError::ReadPolicyError(
                        "get policy name failed".to_string(),
                    ))?;
                let content =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(content.as_bytes());
                policies.insert(name.to_string() + ".rego", content);
            }
        }
        return Ok(policies);
    }

    async fn get_policy(&self, policy_id: &String) -> Result<String, PolicyEngineError> {
        let mut policy_file: PathBuf = self.policy_dir.clone();
        policy_file.push(format!("{}", policy_id));
        let policy = tokio::fs::read(policy_file.as_path())
            .await
            .map_err(|err| PolicyEngineError::ReadPolicyError(format!("read policy failed: {}", err)))?;
        let policy_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        Ok(policy_base64)
    }
}

impl OPA {
    pub async fn new(policy_dir: &String) -> Result<Self, PolicyEngineError> {
        let policy_path = PathBuf::from(policy_dir);
        if !policy_path.as_path().exists() {
            std::fs::create_dir_all(&policy_dir).map_err(|err| {
                PolicyEngineError::CreatePolicyDirError(format!("policy dir create failed: {}", err))
            })?;
        }

        Ok(OPA {
            policy_dir: policy_path,
            default_policy_dir: PathBuf::from(DEFAULT_POLICY_DIR),
            default_policy_vcca: String::from(DEFAULT_VCCA_REGO),
            default_policy_itrustee: String::from(DEFAULT_ITRUSTEE_REGO),
        })
    }
}
