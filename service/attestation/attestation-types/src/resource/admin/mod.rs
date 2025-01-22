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

pub mod simple;

use crate::resource::{error::Result, policy::PolicyLocation, Resource, ResourceLocation};
use async_trait::async_trait;

#[async_trait]
pub trait ResourceAdminInterface: ResourcePolicyAdminInterface + Send + Sync {
    /// Get resource from the storage
    async fn get_resource(&self, location: ResourceLocation) -> Result<Resource>;
    /// Traverse and get resource list in particular vendor.
    async fn list_resource(&self, vendor: &str) -> Result<Vec<ResourceLocation>>;
    /// Add new resource. If the resource already exists, error will be thrown.
    async fn add_resource(
        &self,
        _location: ResourceLocation,
        _content: String,
        _policy: Vec<String>,
    ) -> Result<()>;
    ///  Modify the content of specific resource.
    async fn modify_resource(&self, _location: ResourceLocation, _content: String) -> Result<()>;
    /// Delete resource.
    async fn del_resource(&self, _location: ResourceLocation) -> Result<()>;
    /// Bind policy with resource.
    async fn bind_policy(&self, _location: ResourceLocation, _policy: Vec<String>) -> Result<()>;
    /// Unbind policy with resource.
    async fn unbind_policy(&self, _location: ResourceLocation, _policy: Vec<String>) -> Result<()>;
    /// Evaluate resource according the claims.
    async fn evaluate_resource(&self, _location: ResourceLocation, _claim: &str) -> Result<bool>;
}

#[async_trait]
pub trait ResourcePolicyAdminInterface: Send + Sync {
    /// Create a policy file and write the content inside the file. If it already exists, override it.
    async fn add_policy(&self, _policy: PolicyLocation, _content: &str) -> Result<()>;
    /// Read the policy content from the file.
    async fn get_policy(&self, _policy: PolicyLocation) -> Result<String>;
    /// Delete the policy file.
    async fn delete_policy(&self, _policy: PolicyLocation) -> Result<()>;
    /// Get all existing policy files.
    async fn get_all_policies(&self) -> Result<Vec<PolicyLocation>>;
    /// Get all policy files of a vendor.
    async fn get_all_policies_in_vendor(&self, _vendor: &str) -> Result<Vec<PolicyLocation>>;
    /// Clear all policy files.
    async fn clear_all_policies(&self) -> Result<()>;
    /// Clear all policy files in vendor.
    async fn clear_all_policies_in_vendor(&self, _vendor: &str) -> Result<()>;
}
