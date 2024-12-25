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
    async fn get(&self, location: &str) -> Result<Resource> {
        let regularized = self.regular(location)?;
        Resource::read_from_file(regularized).await
    }

    async fn store(&self, location: &str, resource: Resource) -> Result<()> {
        let regularized = self.regular(location)?;
        tokio::fs::write(regularized, serde_json::to_string(&resource)?)
            .await
            .context("failed to add resource")?;
        Ok(())
    }

    async fn modify(&self, location: &str, content: String) -> Result<()> {
        let regularized = self.regular(location)?;
        let mut resource = Resource::read_from_file(regularized.clone()).await?;
        resource.content = content;
        tokio::fs::write(regularized, resource.to_string()?)
            .await
            .context("failed to modify resource")?;
        Ok(())
    }

    async fn delete(&self, location: &str) -> Result<()> {
        let regularized = self.regular(location)?;
        tokio::fs::remove_file(regularized)
            .await
            .context("failed to delete resource")?;
        Ok(())
    }
}

#[async_trait]
impl PolicyOp for SimpleStorage {
    async fn set_policy(&self, location: &str, policy: Vec<String>) -> Result<()> {
        let mut resource = self.get(location).await?;
        resource.policy = policy;
        self.store(&location, resource).await
    }
    async fn get_all_policy(&self, location: &str) -> Result<Vec<String>> {
        let resource = self.get(location).await?;
        Ok(resource.policy)
    }
    async fn clear_policy(&self, location: &str) -> Result<()> {
        let mut resource = self.get(&location).await?;
        resource.policy = vec![];
        self.store(&location, resource).await
    }
    async fn delte_policy(&self, location: &str, policy: String) -> Result<()> {
        let mut resource = self.get(&location).await?;
        if let Ok(idx) = resource.policy.binary_search(&policy) {
            resource.policy.remove(idx);
        }
        self.store(&location, resource).await
    }
    async fn add_policy(&self, location: &str, policy: String) -> Result<()> {
        let mut resource = self.get(&location).await?;
        resource.policy.push(policy);
        self.store(&location, resource).await
    }
}
