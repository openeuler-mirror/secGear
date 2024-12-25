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

pub(crate) mod opa;

use crate::error::ResourceError;
use crate::error::Result;
use async_trait::async_trait;

/// Manage the policy files and evaluate the legality of resource
#[async_trait]
pub(crate) trait PolicyEngine: Send + Sync {
    /// Given the resource location and claims, read the resource content from the storage and evaluate the resource according to the claims.
    async fn evaluate(&self, _resource: &str, _claims: &str, _policy: Vec<String>) -> Result<bool> {
        Err(ResourceError::NotImplemented)
    }
    /// Create a policy file and write the content inside the file. If it already exists, override it.
    async fn add_policy(&self, _path: &str, _policy: &str) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
    /// Read the policy content from the file.
    async fn get_policy(&self, _path: &str, _policy: &str) -> Result<String> {
        Err(ResourceError::NotImplemented)
    }
    /// Delete the policy file.
    async fn delete_policy(&self, _path: &str) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
    /// List all existing policy files.
    async fn get_all_policy(&self) -> Result<Vec<String>> {
        Err(ResourceError::NotImplemented)
    }
    /// Clear all policy files.
    async fn clear_all_policy(&self) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
}
