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

use crate::admin::ResourceAdminInterface;
use crate::error::Result;
use crate::policy::opa::OpenPolicyAgent;
use crate::policy::{PolicyEngine, PolicyLocation};
use crate::resource::ResourceLocation;
use crate::storage::simple::SimpleStorage;
use crate::storage::StorageEngine;
use anyhow::Context;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::{Resource, ResourcePolicyAdminInterface};

pub struct SimpleResourceAdmin {
    storage_engine: Arc<Mutex<dyn StorageEngine>>,
    policy_engine: Arc<Mutex<dyn PolicyEngine>>,
}

impl SimpleResourceAdmin {
    pub fn new(storage_base: PathBuf, policy_base: PathBuf) -> Self {
        SimpleResourceAdmin {
            storage_engine: Arc::new(Mutex::new(SimpleStorage::new(storage_base))),
            policy_engine: Arc::new(Mutex::new(OpenPolicyAgent::new(policy_base))),
        }
    }

    pub fn default() -> Self {
        SimpleResourceAdmin {
            storage_engine: Arc::new(Mutex::new(SimpleStorage::default())),
            policy_engine: Arc::new(Mutex::new(OpenPolicyAgent::default())),
        }
    }
}

#[async_trait]
impl ResourceAdminInterface for SimpleResourceAdmin {
    async fn get_resource(&self, location: ResourceLocation) -> Result<Resource> {
        self.storage_engine.lock().await.get(location).await
    }

    async fn evaluate_resource(&self, location: ResourceLocation, claims: &str) -> Result<bool> {
        let resource = self
            .get_resource(location.clone())
            .await
            .context("get resource failed")
            .map_err(|e| {
                log::debug!("{}", e);
                e
            })?;
        Ok(self
            .policy_engine
            .lock()
            .await
            .evaluate(location, claims, resource.get_policy())
            .await
            .context("evaluate failed")
            .map_err(|e| {
                log::debug!("{}", e);
                e
            })?)
    }

    // If unmatched policy is found, aborting the adding procedure.
    async fn add_resource(
        &self,
        location: ResourceLocation,
        content: String,
        policy: Vec<String>,
    ) -> Result<()> {
        let mut legal_policy: Vec<PolicyLocation> = vec![];
        for p in policy {
            let p = match PolicyLocation::try_from(p.clone()) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Failed to parse policy '{}': {}", p, e);
                    continue;
                }
            };
            if !location.check_policy_legal(&p) {
                return Err(crate::error::ResourceError::UnmatchedPolicyResource(
                    location.to_string(),
                    p.to_string(),
                ));
            }
            legal_policy.push(p.clone());
        }
        let resource = Resource::new(content, legal_policy);
        self.storage_engine
            .lock()
            .await
            .store(location, resource)
            .await
    }

    async fn del_resource(&self, location: ResourceLocation) -> Result<()> {
        self.storage_engine.lock().await.delete(location).await
    }

    // If unmatched policy is found, aborting the binding procedure.
    async fn bind_policy(&self, location: ResourceLocation, policy: Vec<String>) -> Result<()> {
        let mut legal_policy: Vec<PolicyLocation> = vec![];
        for p in policy.iter() {
            if let Ok(p) = p.parse::<PolicyLocation>() {
                if !location.check_policy_legal(&p) {
                    return Err(crate::error::ResourceError::UnmatchedPolicyResource(
                        location.to_string(),
                        p.to_string(),
                    ));
                }
                legal_policy.push(p);
            }
        }
        self.storage_engine
            .lock()
            .await
            .bind_policies(location, legal_policy)
            .await
    }

    // If unmatched policy is found, aborting the unbinding procedure.
    async fn unbind_policy(&self, location: ResourceLocation, policy: Vec<String>) -> Result<()> {
        let mut legal_policy: Vec<PolicyLocation> = vec![];
        for p in policy.iter() {
            let p = p.parse::<PolicyLocation>()?;
            if !location.check_policy_legal(&p) {
                return Err(crate::error::ResourceError::UnmatchedPolicyResource(
                    location.to_string(),
                    p.to_string(),
                ));
            }
            legal_policy.push(p);
        }
        self.storage_engine
            .lock()
            .await
            .unbind_policies(location, legal_policy)
            .await
    }

    async fn modify_resource(&self, location: ResourceLocation, content: String) -> Result<()> {
        self.storage_engine
            .lock()
            .await
            .modify(location, content)
            .await
    }
}

#[async_trait]
impl ResourcePolicyAdminInterface for SimpleResourceAdmin {
    /// Create a policy file and write the content inside the file. If it already exists, override it.
    async fn add_policy(&self, path: PolicyLocation, policy: &str) -> Result<()> {
        self.policy_engine
            .lock()
            .await
            .add_policy(path, policy)
            .await
    }
    /// Read the policy content from the file.
    async fn get_policy(&self, path: PolicyLocation) -> Result<String> {
        self.policy_engine.lock().await.get_policy(path).await
    }
    /// Delete the policy file.
    async fn delete_policy(&self, path: PolicyLocation) -> Result<()> {
        self.policy_engine.lock().await.delete_policy(path).await
    }
    /// Get all existing policy files.
    async fn get_all_policies(&self) -> Result<Vec<PolicyLocation>> {
        self.policy_engine.lock().await.get_all_policy().await
    }
    /// Get all policy files of a vendor.
    async fn get_all_policies_in_vendor(&self, vendor: &str) -> Result<Vec<PolicyLocation>> {
        self.policy_engine
            .lock()
            .await
            .get_all_policy_in_vendor(vendor)
            .await
    }
    /// Clear all policy files.
    async fn clear_all_policies(&self) -> Result<()> {
        self.policy_engine.lock().await.clear_all_policy().await
    }
    /// Clear all policy files in vendor.
    async fn clear_all_policies_in_vendor(&self, vendor: &str) -> Result<()> {
        self.policy_engine
            .lock()
            .await
            .clear_all_policy_in_vendor(vendor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{admin::ResourceAdminInterface, resource::ResourceLocation};
    use std::env;
    use tokio::runtime::Runtime;

    #[test]
    fn test_admin_unbind_policy() {
        let cwd = env::current_dir().unwrap();
        let storage_base = cwd.join("storage");
        let policy_base = cwd.join("policy");
        let tmp_vendor = "test_admin_unbind_policy";
        let tmp_resource = "test";
        let vendor_path = storage_base.join(tmp_vendor);
        let resource_path = storage_base.join(tmp_vendor).join(tmp_resource);
        let admin = super::SimpleResourceAdmin::new(storage_base.clone(), policy_base.clone());
        std::fs::create_dir_all(&vendor_path).unwrap();
        std::fs::File::create(&resource_path).unwrap();
        let resource = r#"{
        "content": "hello",
        "policy": ["test_admin_unbind_policy/c.rego", "test_admin_unbind_policy/a.rego", "default/b.rego", "test_admin_unbind_policy/b.rego"]
}"#;
        std::fs::write(&resource_path, resource).unwrap();

        let location =
            ResourceLocation::new(Some(tmp_vendor.to_string()), tmp_resource.to_string());
        let unbind_policy = vec![
            "default/b.rego".to_string(),
            "test_admin_unbind_policy/b.rego".to_string(),
        ];

        let runtime = Runtime::new().unwrap();
        runtime
            .block_on(admin.unbind_policy(location.clone(), unbind_policy))
            .unwrap();
        let r = runtime.block_on(admin.get_resource(location)).unwrap();
        let content = r.to_string().unwrap();
        println!("{}", r.to_string().unwrap());
        assert_eq!(
            content,
            r#"{"content":"hello","policy":["test_admin_unbind_policy/a.rego","test_admin_unbind_policy/c.rego"]}"#
        );

        std::fs::remove_dir_all(&storage_base).unwrap();
    }
}
