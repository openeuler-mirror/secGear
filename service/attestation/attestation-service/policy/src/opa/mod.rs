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
    default_policy: String,
}

impl PolicyEngine for OPA {
    /// refs comes from report, by using query reference API
    async fn evaluate(
        &self,
        refs: &String,
        data_for_policy: &String,
        policy_id: &Vec<String>,
    ) -> Result<HashMap<String, String>, PolicyEngineError> {
        let mut policy_id_use = policy_id.clone();
        if policy_id_use.is_empty() {
            policy_id_use.push(String::from("default.rego"));
        }
        let mut result: HashMap<String, String> = HashMap::new();
        for id in policy_id_use {
            let policy_path: String = format!(
                "{}/{}",
                self.policy_dir
                    .to_str()
                    .ok_or(PolicyEngineError::InvalidPolicyDir(
                        "policy directory error".to_string()
                    ))?,
                id
            );
            let engine_policy = tokio::fs::read_to_string(policy_path).await.map_err(|_| {
                PolicyEngineError::ReadPolicyError("read policy failed".to_string())
            })?;

            let mut engine = regorus::Engine::new();
            engine.add_policy(id.clone(), engine_policy).map_err(|_| {
                PolicyEngineError::EngineLoadPolicyError("policy load failed".to_string())
            })?;

            let input = Value::from_json_str(refs).map_err(|_| {
                PolicyEngineError::InvalidReport("report to Value failed".to_string())
            })?;
            engine.set_input(input);

            if !data_for_policy.is_empty() {
                let data = Value::from_json_str(data_for_policy).map_err(|_| {
                    PolicyEngineError::EngineLoadDataError("data to Value failed".to_string())
                })?;
                engine.add_data(data).map_err(|_| {
                    PolicyEngineError::EngineLoadDataError("engine add data failed".to_string())
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
            .map_err(|_| PolicyEngineError::InvalidPolicy("policy decode failed".to_string()))?;

        let mut policy_file: PathBuf = self.policy_dir.clone();
        policy_file.push(format!("{}", policy_id));
        tokio::fs::write(policy_file.as_path(), &raw)
            .await
            .map_err(|_| PolicyEngineError::WritePolicyError("write policy failed".to_string()))?;
        Ok(())
    }

    async fn get_all_policy(&self) -> Result<HashMap<String, String>, PolicyEngineError> {
        let mut items = tokio::fs::read_dir(&self.policy_dir.as_path())
            .await
            .map_err(|_| PolicyEngineError::ReadPolicyError("read policy failed".to_string()))?;
        let mut policies = HashMap::new();
        while let Some(item) = items
            .next_entry()
            .await
            .map_err(|_| PolicyEngineError::ReadPolicyError("read policy failed".to_string()))?
        {
            let path = item.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rego") {
                let content: String =
                    tokio::fs::read_to_string(path.clone()).await.map_err(|_| {
                        PolicyEngineError::ReadPolicyError("read policy failed".to_string())
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
            .map_err(|_| PolicyEngineError::ReadPolicyError("read policy failed".to_string()))?;
        let policy_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        Ok(policy_base64)
    }
}

impl OPA {
    pub async fn new(policy_dir: &String) -> Result<Self, PolicyEngineError> {
        let policy_path = PathBuf::from(policy_dir);
        if !policy_path.as_path().exists() {
            std::fs::create_dir_all(&policy_dir).map_err(|_| {
                PolicyEngineError::CreatePolicyDirError("policy dir create failed".to_string())
            })?;
        }

        let mut default_policy_path = policy_path.clone();
        default_policy_path.push("default.rego");
        if !default_policy_path.clone().as_path().exists() {
            // default policy not exist，creat it, use template file
            let init_default_policy = std::include_str!("default.rego").to_string();
            let _ =
                std::fs::write(default_policy_path.clone(), init_default_policy).map_err(|_| {
                    PolicyEngineError::WritePolicyError("write default policy failed".to_string())
                });
        }

        Ok(OPA {
            policy_dir: policy_path,
            default_policy: String::from(default_policy_path.into_os_string().to_str().unwrap()),
        })
    }
}
