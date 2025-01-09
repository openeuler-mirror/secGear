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

pub(crate) mod simple;

use crate::error::ResourceError;
use crate::error::Result;
use crate::policy::PolicyLocation;
use crate::resource::Resource;
use crate::resource::ResourceLocation;
use async_trait::async_trait;

#[async_trait]
pub(crate) trait StorageEngine: StorageOp + PolicyOp {}

#[async_trait]
pub(crate) trait StorageOp: Send + Sync {
    /// Get the resource inside the storage and return a structure instance.
    async fn get(&self, location: ResourceLocation) -> Result<Resource>;
    /// Traverse and collect resource list in particular vendor.
    async fn list(&self, vendor: &str) -> Result<Vec<ResourceLocation>>;
    /// Create a new resource if it does not exist. If the resource already exists, it will be overrided.
    async fn store(&self, location: ResourceLocation, resource: Resource) -> Result<()>;
    /// Override the content field in the resource, while keep other fields the same.
    async fn modify(&self, location: ResourceLocation, content: String) -> Result<()>;
    /// Delete the resource inside the storage.
    async fn delete(&self, location: ResourceLocation) -> Result<()>;
    /// Flush the buffer into the storage
    async fn flush(&self) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
}

#[async_trait]
pub(crate) trait PolicyOp: StorageOp + Send + Sync {
    /// Clear the original policy and set the new ones.
    async fn set_policies(
        &self,
        location: ResourceLocation,
        policy: Vec<PolicyLocation>,
    ) -> Result<()>;
    /// Get all policy from the resource.
    async fn get_all_policies(&self, location: ResourceLocation) -> Result<Vec<PolicyLocation>>;
    /// Clear the original policy inside the resource.
    async fn clea_policies(&self, location: ResourceLocation) -> Result<()>;
    /// Delete the specific policy from the resource.
    async fn unbind_policies(
        &self,
        location: ResourceLocation,
        policy: Vec<PolicyLocation>,
    ) -> Result<()>;
    /// Append new policy inside the resource.
    async fn bind_policies(
        &self,
        location: ResourceLocation,
        policies: Vec<PolicyLocation>,
    ) -> Result<()>;
}
