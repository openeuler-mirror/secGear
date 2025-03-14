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

use super::PolicyLocation;
use crate::resource::{
    error::{ResourceError, Result},
    policy::PolicyEngine,
    ResourceLocation, DEFAULT_VENDOR_BASE,
};
use anyhow::Context;
use async_trait::async_trait;
use std::path::PathBuf;

pub(crate) const DEFAULT_RESOURCE_POLICY_DIR: &str =
    "/etc/attestation/attestation-service/resource/policy/";
pub(crate) const DEFAULT_RESOURCE_VIRTCCA_DEFAULT_POLICY: &str = "virtcca.rego";

pub(crate) struct OpenPolicyAgent {
    base: PathBuf,
}

impl OpenPolicyAgent {
    pub(crate) fn new(base: PathBuf) -> Self {
        OpenPolicyAgent { base }
    }

    pub(crate) fn regular_policy(&self, policy: &PolicyLocation) -> Result<PathBuf> {
        let p = policy.to_string();
        if !policy.check_legal() {
            return Err(ResourceError::IllegalPolicyLocation(p));
        }

        Ok(self.base.join(p))
    }

    pub(crate) fn regular_vendor(&self, vendor: &str) -> Result<PathBuf> {
        if !Self::check_vendor_legal(vendor) {
            return Err(ResourceError::IllegalVendor(vendor.to_string()));
        }

        let v = if vendor.is_empty() {
            DEFAULT_VENDOR_BASE
        } else {
            vendor
        };

        Ok(self.base.join(v))
    }

    pub(crate) fn check_vendor_legal(vendor: &str) -> bool {
        if vendor.contains(['.', '/']) {
            return false;
        }
        true
    }

    pub fn default() -> Self {
        Self::new(PathBuf::from(DEFAULT_RESOURCE_POLICY_DIR))
    }
}

#[async_trait]
impl PolicyEngine for OpenPolicyAgent {
    async fn evaluate(
        &self,
        resource: ResourceLocation,
        claim: &str,
        policy: Vec<PolicyLocation>,
    ) -> Result<bool> {
        let mut engine = regorus::Engine::new();
        let mut eval_targets: Vec<String> = vec![];

        if policy.is_empty() {
            /* Apply default policy according to the tee type from the claims. */
            let claim_json: serde_json::Value = serde_json::from_str(claim)?;
            if let Some(tee) = claim_json.get("tee") {
                if let Some(tee_str) = tee.as_str() {
                    match tee_str {
                        "vcca" => {
                            engine
                                .add_policy_from_file(
                                    self.base
                                        .join(DEFAULT_VENDOR_BASE)
                                        .join(DEFAULT_RESOURCE_VIRTCCA_DEFAULT_POLICY),
                                )
                                .context("failed to add policy from file")?;
                            let vendor = DEFAULT_VENDOR_BASE;
                            let id = match DEFAULT_RESOURCE_VIRTCCA_DEFAULT_POLICY
                                .strip_suffix(".rego")
                            {
                                Some(v) => v,
                                None => {
                                    log::debug!(
                                        "Invalid default policy id '{}'",
                                        DEFAULT_RESOURCE_VIRTCCA_DEFAULT_POLICY
                                    );
                                    return Err(ResourceError::IllegalPolicySuffix(
                                        DEFAULT_RESOURCE_VIRTCCA_DEFAULT_POLICY.to_string(),
                                    ));
                                }
                            };
                            eval_targets.push(format!("data.{}.{}.allow", vendor, id))
                        }
                        _ => {}
                    }
                }
            }
        }

        for file in policy.iter() {
            let sub_id = match file.id.strip_suffix(".rego") {
                Some(v) => v,
                None => {
                    log::debug!("Invalid policy id '{}'", file);
                    return Err(ResourceError::IllegalPolicySuffix(file.to_string()));
                }
            };
            let p: PathBuf = file.try_into()?;
            if let Err(e) = engine.add_policy_from_file(self.base.join(p)) {
                log::debug!("Failed to add policy: {}", e);
                return Err(e.into());
            }
            // .context("failed to add policy from file")?;
            eval_targets.push(format!(
                "data.{}.{}.allow",
                file.vendor
                    .clone()
                    .unwrap_or(DEFAULT_VENDOR_BASE.to_string()),
                sub_id
            ))
        }
        log::debug!("Evaluate query targest: {:?}", eval_targets);
        if let Err(e) = engine.add_data_json(&format!("{{\"resource\":\"{}\"}}", resource)) {
            log::debug!("Failed to add resource data: {}", e);
            return Err(e.into());
        }
        if let Err(e) = engine.set_input_json(claim) {
            log::debug!("Failed to set input claim: {}", e);
            return Err(e.into());
        }

        let mut ret = true;

        for eval in eval_targets {
            let v = match engine.eval_bool_query(eval.clone(), false) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("Failed to evaluate {}: {}", eval, e);
                    return Err(e.into());
                }
            };
            log::debug!("Evaluate {} = {}", eval, v);
            ret = ret && v;
        }

        Ok(ret)
    }

    async fn get_policy(&self, path: PolicyLocation) -> Result<String> {
        let p = self.regular_policy(&path)?;
        let raw = tokio::fs::read(p).await?;
        Ok(String::from_utf8(raw)?)
    }

    async fn add_policy(&self, path: PolicyLocation, policy: &str) -> Result<()> {
        let p = self.regular_policy(&path)?;
        if let Some(parent) = p.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                log::warn!(
                    "Failed to create vendor directory for policy '{}': {}",
                    path,
                    e
                );
            }
        }
        tokio::fs::write(p, policy.as_bytes()).await?;
        Ok(())
    }

    async fn delete_policy(&self, path: PolicyLocation) -> Result<()> {
        let p = self.regular_policy(&path)?;
        tokio::fs::remove_file(p).await?;
        Ok(())
    }

    async fn get_all_policy(&self) -> Result<Vec<PolicyLocation>> {
        let mut ret: Vec<PolicyLocation> = vec![];
        let mut dir = tokio::fs::read_dir(&self.base).await?;
        while let Some(d) = dir.next_entry().await? {
            match d.file_type().await {
                Ok(t) => {
                    if !t.is_dir() {
                        continue;
                    }
                }
                Err(_) => {
                    continue;
                }
            }

            let vendor = match d.file_name().into_string() {
                Ok(s) => s,
                Err(s) => {
                    log::warn!("Illegal policy vendor directory '{:?}'", s);
                    continue;
                }
            };

            let mut several = match self.get_all_policy_in_vendor(&vendor).await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("Failed to get policy from vendor '{}': {}", vendor, e);
                    continue;
                }
            };

            ret.append(&mut several);
        }

        Ok(ret)
    }

    async fn get_all_policy_in_vendor(&self, vendor: &str) -> Result<Vec<PolicyLocation>> {
        let vendor_dir = self.regular_vendor(vendor)?;
        let mut dir = tokio::fs::read_dir(vendor_dir).await?;
        let mut ret: Vec<PolicyLocation> = vec![];
        while let Some(d) = dir.next_entry().await? {
            if let Ok(t) = d.file_type().await {
                if !t.is_file() {
                    continue;
                }
            }

            let rego = match d.file_name().into_string() {
                Ok(s) => s,
                Err(s) => {
                    log::warn!("Illegal policy file name '{:?}'", s);
                    continue;
                }
            };
            if !rego.ends_with("rego") {
                continue;
            }

            ret.push(PolicyLocation {
                vendor: if vendor == DEFAULT_VENDOR_BASE {
                    None
                } else {
                    Some(vendor.to_string())
                },
                id: rego,
            });
        }

        Ok(ret)
    }

    async fn clear_all_policy(&self) -> Result<()> {
        let mut dir = tokio::fs::read_dir(&self.base).await?;
        while let Some(d) = dir.next_entry().await? {
            match d.file_type().await {
                Ok(t) => {
                    if !t.is_dir() {
                        continue;
                    }
                }
                Err(_) => {
                    continue;
                }
            }

            match d.file_name().into_string() {
                Ok(s) => {
                    if let Err(e) = self.clear_all_policy_in_vendor(&s).await {
                        log::warn!("Failed to clear vendor '{}': {}", s, e);
                    }
                }
                Err(e) => {
                    log::warn!("Illegal vendor directory name '{:?}'", e);
                    continue;
                }
            }
        }
        Ok(())
    }

    async fn clear_all_policy_in_vendor(&self, vendor: &str) -> Result<()> {
        let vendor_dir = self.regular_vendor(vendor)?;
        let md = tokio::fs::metadata(&vendor_dir)
            .await
            .context("fetching metadata failed")?;
        if md.is_dir() {
            tokio::fs::remove_dir_all(vendor_dir).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime;

    use super::ResourceLocation;
    use super::{OpenPolicyAgent, PolicyEngine};

    #[test]
    fn test_evaluate() {
        let pwd = std::env::current_dir().expect("failed to get pwd");
        let opa = OpenPolicyAgent::new(pwd.join("src/policy/opa"));
        let resource = ResourceLocation::new(None, "b/p/f".to_string());
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
