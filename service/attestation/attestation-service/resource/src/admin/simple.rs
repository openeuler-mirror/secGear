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
use std::sync::Arc;
use tokio::sync::Mutex;

use super::{Resource, ResourcePolicyAdminInterface};

pub struct SimpleResourceAdmin {
    storage_engine: Arc<Mutex<dyn StorageEngine>>,
    policy_engine: Arc<Mutex<dyn PolicyEngine>>,
}

impl SimpleResourceAdmin {
    pub fn new() -> Self {
        SimpleResourceAdmin {
            storage_engine: Arc::new(Mutex::new(SimpleStorage::default())),
            policy_engine: Arc::new(Mutex::new(OpenPolicyAgent::default())),
        }
    }

    pub fn default() -> Self {
        Self::new()
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
    async fn add_resource(
        &self,
        location: ResourceLocation,
        content: String,
        policy: Vec<String>,
    ) -> Result<()> {
        // Filter illegal policy that has different vendor with the resource.
        let mut legal_policy: Vec<PolicyLocation> = vec![];
        for p in policy {
            let p = match PolicyLocation::try_from(p.clone()) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Failed to parse policy '{}': {}", p, e);
                    continue;
                }
            };

            if let Some(policy_vendor) = p.vendor.as_ref() {
                if policy_vendor.as_str() == "default" {
                    legal_policy.push(p.clone());
                } else {
                    if let Some(resource_vendor) = location.vendor.as_ref() {
                        if resource_vendor == policy_vendor {
                            legal_policy.push(p.clone());
                            continue;
                        }
                    }

                    log::warn!(
                        "Illegal policy {}, resource vendor is {}",
                        p,
                        location.vendor.clone().unwrap_or("default".to_string())
                    );
                }
            }
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

    async fn bind_policy(&self, location: ResourceLocation, policy: Vec<String>) -> Result<()> {
        let mut legal_policy: Vec<PolicyLocation> = vec![];
        for p in policy.iter() {
            if let Ok(legal) = p.parse::<PolicyLocation>() {
                legal_policy.push(legal);
            }
        }
        self.storage_engine
            .lock()
            .await
            .bind_policies(location, legal_policy)
            .await
    }

    async fn unbind_policy(&self, location: ResourceLocation, policy: Vec<String>) -> Result<()> {
        let mut legal_policy: Vec<PolicyLocation> = vec![];
        for p in policy.iter() {
            if let Ok(legal) = p.parse::<PolicyLocation>() {
                legal_policy.push(legal);
            }
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
