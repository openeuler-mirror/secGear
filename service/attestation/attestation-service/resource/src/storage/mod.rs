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
use crate::resource::Resource;
use async_trait::async_trait;

#[async_trait]
pub(crate) trait StorageEngine: StorageOp + PolicyOp {}

#[async_trait]
pub(crate) trait StorageOp: Send + Sync {
    /// Get the resource inside the storage and return a structure instance.
    async fn get(&self, location: &str) -> Result<Resource>;
    /// Create a new resource if it does not exist. If the resource already exists, it will be overrided.
    async fn store(&self, location: &str, resource: Resource) -> Result<()>;
    /// Override the content field in the resource, while keep other fields the same.
    async fn modify(&self, location: &str, content: String) -> Result<()>;
    /// Delete the resource inside the storage.
    async fn delete(&self, location: &str) -> Result<()>;
    /// Flush the buffer into the storage
    async fn flush(&self) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
}

#[async_trait]
pub(crate) trait PolicyOp: StorageOp + Send + Sync {
    /// Clear the original policy and set the new ones.
    async fn set_policy(&self, location: &str, policy: Vec<String>) -> Result<()>;
    /// Get all policy from the resource.
    async fn get_all_policy(&self, location: &str) -> Result<Vec<String>>;
    /// Clear the original policy inside the resource.
    async fn clear_policy(&self, location: &str) -> Result<()>;
    /// Delete the specific policy from the resource.
    async fn delte_policy(&self, location: &str, policy: String) -> Result<()>;
    /// Append new policy inside the resource.
    async fn add_policy(&self, location: &str, policy: String) -> Result<()>;
}
