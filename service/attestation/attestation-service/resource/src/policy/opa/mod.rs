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
    policy::PolicyEngine,
};
use anyhow::Context;
use async_trait::async_trait;
use std::{fs::read_to_string, path::PathBuf};

const DEFAULT_RESOURCE_POLICY_DIR: &str = "/run/attestation/attestation-service/resource/policy/";
const DEFAULT_RESOURCE_VIRTCCA_DEFAULT_POLICY: &str = "default_virtcca.rego";

pub(crate) struct OpenPolicyAgent {
    base: PathBuf,
}

impl OpenPolicyAgent {
    pub(crate) fn new(base: PathBuf) -> Self {
        OpenPolicyAgent { base }
    }

    pub fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_RESOURCE_POLICY_DIR))
    }
}

#[async_trait]
impl PolicyEngine for OpenPolicyAgent {
    async fn evaluate(&self, resource: &str, claim: &str, policy: Vec<String>) -> Result<bool> {
        let mut engine = regorus::Engine::new();

        /* Apply default policy according to the tee type from the claims. */
        let claim_json: serde_json::Value = serde_json::from_str(claim)?;
        if let Some(tee) = claim_json.get("tee") {
            if let Some(tee_str) = tee.as_str() {
                match tee_str {
                    "vcca" => {
                        engine
                            .add_policy_from_file(
                                self.base.join(DEFAULT_RESOURCE_VIRTCCA_DEFAULT_POLICY),
                            )
                            .context("failed to add policy from file")?;
                    }
                    _ => {}
                }
            }
        }
        for file in policy.iter() {
            engine
                .add_policy_from_file(file)
                .context("failed to add policy from file")?;
        }
        engine
            .add_data_json(&format!("{{\"resource\":\"{}\"}}", resource))
            .context("failed to add data json")?;
        engine
            .set_input_json(claim)
            .context("failed to set input json")?;

        Ok(engine.eval_bool_query("data.policy.allow".to_string(), false)?)
    }
    /// Read the policy content from the file.
    async fn get_policy(&self, _path: &str, _policy: &str) -> Result<String> {
        Err(ResourceError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime;

    use super::{OpenPolicyAgent, PolicyEngine};

    #[test]
    fn test_evaluate() {
        let pwd = std::env::current_dir().expect("failed to get pwd");
        let opa = OpenPolicyAgent::new(pwd.join("src/policy/opa"));
        let resource = "b/p/f";
        let claims = r#"
{
    "iss": "oeas",
    "iat": 1735635443,
    "nbf": 1735635443,
    "exp": 1735635743,
    "evaluation_reports": {
        "eval_result": true,
        "policy": [],
        "report": {
            "default_vcca.rego": "{\"vcca.cvm.rim\":\"1ee366339c8245a34a8ad9d27a0b912a588af7da8aef514ae8dec22746956dd1\"}",
            "ima": {}
        }
    },
    "tee": "vcca",
    "tcb_status": {
        "vcca.cvm.challenge": "586667776b4972524b58684550524f384771654c7244695356485134715f372d4e36375064587a50457763000000000000000000000000000000000000000000",
        "vcca.cvm.rem.0": "927b62bc7f4d9fd03afd0b9b2fe8832004b570b4c4bffc2949c4e461b0a0ff63",
        "vcca.cvm.rem.1": "0000000000000000000000000000000000000000000000000000000000000000",
        "vcca.cvm.rem.2": "0000000000000000000000000000000000000000000000000000000000000000",
        "vcca.cvm.rem.3": "0000000000000000000000000000000000000000000000000000000000000000",
        "vcca.cvm.rim": "1ee366339c8245a34a8ad9d27a0b912a588af7da8aef514ae8dec22746956dd1",
        "vcca.cvm.rpv": "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "vcca.platform": ""
    }   
}"#;
        let policy = vec![];
        let rt = runtime::Runtime::new().unwrap();
        let r = rt.block_on(opa.evaluate(resource, claims, policy));
        assert_eq!(r.unwrap(), true);
    }
}
