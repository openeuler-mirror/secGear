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

use crate::{
    error::{ResourceError, Result},
    policy::ResourcePolicyEngine,
};
use anyhow::Context;
use async_trait::async_trait;
use std::path::PathBuf;

const DEFAULT_RESOURCE_POLICY_DIR: &str = "/etc/attestation/attestation-service/resource/policy/";
const DEFAULT_RESOURCE_POLICY: &str = "default.rego";

pub struct ResourceOPA {
    policy_path: PathBuf,
}

impl ResourceOPA {
    pub fn new(policy_path: PathBuf) -> Result<Self> {
        if policy_path.exists() {
            return Ok(ResourceOPA { policy_path });
        } else {
            log::warn!("Policy does not exist: {:?}", policy_path);
            log::warn!("Use default policy.");
        }

        let default_policy = PathBuf::from(format!(
            "{}{}",
            DEFAULT_RESOURCE_POLICY_DIR, DEFAULT_RESOURCE_POLICY
        ));

        if !default_policy.exists() {
            log::error!("Default policy missing!");
            return Err(ResourceError::PolicyMissing);
        }

        Ok(ResourceOPA {
            policy_path: default_policy,
        })
    }

    pub fn default() -> Self {
        Self::new(PathBuf::from(format!(
            "{}{}",
            DEFAULT_RESOURCE_POLICY_DIR, DEFAULT_RESOURCE_POLICY
        )))
        .unwrap()
    }
}

#[async_trait]
impl ResourcePolicyEngine for ResourceOPA {
    async fn evaluate(&self, resource: &str, claim: &str) -> Result<bool> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy_from_file(self.policy_path.clone())
            .context("failed to add policy from file")?;
        engine
            .add_data_json(&format!("{{\"resource\":\"{}\"}}", resource))
            .context("failed to add data json")?;
        engine
            .set_input_json(claim)
            .context("failed to set input json")?;

        Ok(engine.eval_bool_query("data.policy.allow".to_string(), false)?)
    }
    async fn set_policy(&self, _policy: &str) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
    async fn get_policy(&self, _policy: &str) -> Result<String> {
        Err(ResourceError::NotImplemented)
    }
}
