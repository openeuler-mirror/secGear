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

use crate::resource::error::ResourceError;
use crate::resource::error::Result;
use crate::resource::policy::PolicyLocation;
use crate::resource::storage::StorageOp;
use crate::resource::utils::traverse_regular_file;
use crate::resource::ResourceLocation;
use anyhow::Context;
use async_trait::async_trait;
use std::path::PathBuf;

use super::PolicyOp;
use super::Resource;
use super::StorageEngine;

pub(crate) const STORAGE_BASE: &str = "/etc/attestation/attestation-service/resource/storage/";

pub(crate) struct SimpleStorage {
    base: PathBuf,
}

impl SimpleStorage {
    pub(crate) fn new(base: PathBuf) -> Self {
        Self { base }
    }

    pub(crate) fn default() -> Self {
        Self::new(PathBuf::from(STORAGE_BASE))
    }

    /// Resource location can not contain dot characters to avoid visiting parent directory. All the resource is stored under the base directory.
    fn regular(&self, location: &str) -> Result<PathBuf> {
        /* abandon passing relative path */
        if !self.check_legal(location) {
            return Err(ResourceError::IllegalResource(location.to_string()));
        }
        let base = PathBuf::from(&self.base);
        let path = base.join(location);
        Ok(path)
    }

    fn check_legal(&self, location: &str) -> bool {
        !location.contains(|c| ['.'].contains(&c))
    }
}

#[async_trait]
impl StorageEngine for SimpleStorage {}

#[async_trait]
impl StorageOp for SimpleStorage {
    async fn get(&self, location: ResourceLocation) -> Result<Resource> {
        let regularized = self.regular(&format!("{}", location))?;
        Resource::read_from_file(regularized).await
    }

    async fn list(&self, vendor: &str) -> Result<Vec<ResourceLocation>> {
        let vendor_base = self.regular(vendor)?;
        let resource_list = traverse_regular_file(&vendor_base).await?;
        let mut ret: Vec<ResourceLocation> = vec![];
        for p in resource_list.iter() {
            let path = p.strip_prefix(&vendor_base)?;
            let resource = ResourceLocation::new(
                Some(vendor.to_string()),
                path.to_str()
                    .ok_or(ResourceError::IllegalResource(format!("{:?}", path)))?
                    .to_string(),
            );
            ret.push(resource);
        }
        Ok(ret)
    }

    async fn store(
        &self,
        location: ResourceLocation,
        resource: Resource,
        force: bool,
    ) -> Result<()> {
        let regularized = self.regular(&format!("{}", location))?;

        if !force && regularized.exists() {
            return Err(ResourceError::ResourceExist(location.to_string()));
        }

        if let Some(parent) = regularized.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                log::warn!(
                    "Failed to create vendor directory for resource '{}': {}",
                    location,
                    e
                );
            }
        }
        tokio::fs::write(regularized, serde_json::to_string(&resource)?)
            .await
            .context("failed to add resource")?;
        Ok(())
    }

    async fn modify(&self, location: ResourceLocation, content: String) -> Result<()> {
        let regularized = self.regular(&format!("{}", location))?;
        let mut resource = Resource::read_from_file(regularized.clone()).await?;
        resource.content = content;
        tokio::fs::write(regularized, resource.to_string()?)
            .await
            .context("failed to modify resource")?;
        Ok(())
    }

    async fn delete(&self, location: ResourceLocation) -> Result<()> {
        let regularized = self.regular(&format!("{}", location))?;
        tokio::fs::remove_file(regularized)
            .await
            .context("failed to delete resource")?;
        Ok(())
    }
}

#[async_trait]
impl PolicyOp for SimpleStorage {
    async fn set_policies(
        &self,
        location: ResourceLocation,
        policy: Vec<PolicyLocation>,
    ) -> Result<()> {
        let mut resource = self.get(location.clone()).await?;
        resource.set_policy(policy);
        self.store(location, resource, true).await
    }
    async fn get_all_policies(&self, location: ResourceLocation) -> Result<Vec<PolicyLocation>> {
        let resource = self.get(location).await?;
        Ok(resource.get_policy())
    }
    async fn clear_policies(&self, location: ResourceLocation) -> Result<()> {
        let mut resource = self.get(location.clone()).await?;
        resource.policy = vec![];
        self.store(location, resource, true).await
    }
    async fn unbind_policies(
        &self,
        location: ResourceLocation,
        policy: Vec<PolicyLocation>,
    ) -> Result<()> {
        let mut resource = self.get(location.clone()).await?;
        resource.policy.sort();
        for p in policy.iter() {
            if let Ok(idx) = resource.policy.binary_search(&format!("{}", p)) {
                resource.policy.remove(idx);
            }
        }
        self.store(location, resource, true).await
    }
    async fn bind_policies(
        &self,
        location: ResourceLocation,
        policy: Vec<PolicyLocation>,
    ) -> Result<()> {
        let mut resource = self.get(location.clone()).await?;
        for p in policy.iter() {
            resource.policy.push(format!("{}", p));
        }
        self.store(location.clone(), resource, true).await
    }
}

#[cfg(test)]
mod tests {
    use crate::resource::{policy::PolicyLocation, ResourceLocation};
    use std::env;
    use tokio::runtime::Runtime;

    use super::{PolicyOp, StorageOp};

    #[test]
    fn test_unbind_policies() {
        let cwd = env::current_dir().unwrap();
        let tmp_vendor = "test_unbind_policies";
        let tmp_resource = "test";
        let vendor_path = cwd.join(tmp_vendor);
        let resource_path = cwd.join(tmp_vendor).join(tmp_resource);
        let storage = super::SimpleStorage::new(cwd);
        std::fs::create_dir_all(&vendor_path).unwrap();
        std::fs::File::create(&resource_path).unwrap();
        let resource = r#"{
        "content": "hello",
        "policy": ["test_unbind_policies/c.rego", "test_unbind_policies/a.rego", "default/b.rego", "test_unbind_policies/b.rego"]
}"#;
        std::fs::write(&resource_path, resource).unwrap();

        let location =
            ResourceLocation::new(Some(tmp_vendor.to_string()), tmp_resource.to_string());
        let unbind_policy = vec![
            "default/b.rego".parse::<PolicyLocation>().unwrap(),
            "test_unbind_policies/b.rego"
                .parse::<PolicyLocation>()
                .unwrap(),
        ];

        let runtime = Runtime::new().unwrap();
        runtime
            .block_on(storage.unbind_policies(location.clone(), unbind_policy))
            .unwrap();
        let r = runtime.block_on(storage.get(location)).unwrap();
        let content = r.to_string().unwrap();
        println!("{}", r.to_string().unwrap());
        assert_eq!(
            content,
            r#"{"content":"hello","policy":["test_unbind_policies/a.rego","test_unbind_policies/c.rego"]}"#
        );

        std::fs::remove_dir_all(&vendor_path).unwrap();
    }
}
