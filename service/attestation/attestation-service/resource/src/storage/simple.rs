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

use crate::error::ResourceError;
use crate::error::Result;
use crate::policy::PolicyLocation;
use crate::resource::ResourceLocation;
use crate::storage::StorageOp;
use anyhow::Context;
use async_trait::async_trait;
use std::path::PathBuf;

use super::PolicyOp;
use super::Resource;
use super::StorageEngine;

const STORAGE_BASE: &str = "/run/attestation/attestation-service/resource/storage/";

pub(crate) struct SimpleStorage {
    base: String,
}

impl SimpleStorage {
    pub(crate) fn new(base: String) -> Self {
        Self { base }
    }

    pub(crate) fn default() -> Self {
        Self::new(STORAGE_BASE.to_string())
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

    async fn store(&self, location: ResourceLocation, resource: Resource) -> Result<()> {
        let regularized = self.regular(&format!("{}", location))?;
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
        self.store(location, resource).await
    }
    async fn get_all_policies(&self, location: ResourceLocation) -> Result<Vec<PolicyLocation>> {
        let resource = self.get(location).await?;
        Ok(resource.get_policy())
    }
    async fn clea_policies(&self, location: ResourceLocation) -> Result<()> {
        let mut resource = self.get(location.clone()).await?;
        resource.policy = vec![];
        self.store(location, resource).await
    }
    async fn unbind_policies(
        &self,
        location: ResourceLocation,
        policy: Vec<PolicyLocation>,
    ) -> Result<()> {
        let mut resource = self.get(location.clone()).await?;
        for p in policy.iter() {
            if let Ok(idx) = resource.policy.binary_search(&format!("{}", p)) {
                resource.policy.remove(idx);
            }
        }
        self.store(location, resource).await
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
        self.store(location.clone(), resource).await
    }
}
