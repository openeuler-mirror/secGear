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

use crate::resource::error::ResourceError;
use crate::resource::error::Result;
use crate::resource::ResourceLocation;
use crate::resource::DEFAULT_VENDOR_BASE;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;

/// This structure indicates unique policy location under specific base directory.
/// The base directory should be maintained by the policy management engine.
/// If vendor is none, it should keep the same with the resource vendor.
///
/// To simplify the expression, the policy location can be expressed like 'vendor/policy.rego'.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyLocation {
    pub vendor: Option<String>,
    pub id: String,
}

impl std::convert::From<PolicyLocation> for String {
    fn from(value: PolicyLocation) -> Self {
        format!("{}", value)
    }
}

impl std::convert::From<&PolicyLocation> for String {
    fn from(value: &PolicyLocation) -> Self {
        format!("{}", value)
    }
}

impl std::convert::TryFrom<PolicyLocation> for PathBuf {
    type Error = ResourceError;

    fn try_from(value: PolicyLocation) -> std::result::Result<PathBuf, Self::Error> {
        let path: String = value.into();
        Ok(PathBuf::from_str(&path)?)
    }
}

impl std::convert::TryFrom<&PolicyLocation> for PathBuf {
    type Error = ResourceError;

    fn try_from(value: &PolicyLocation) -> std::result::Result<PathBuf, Self::Error> {
        Ok(PathBuf::from_str(&format!("{}", value))?)
    }
}

impl Display for PolicyLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.vendor
                .clone()
                .unwrap_or(DEFAULT_VENDOR_BASE.to_string()),
            self.id,
        )
    }
}

impl std::convert::TryFrom<String> for PolicyLocation {
    type Error = ResourceError;
    fn try_from(value: String) -> Result<Self> {
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() != 2 {
            return Err(ResourceError::IllegalPolicyLocation(value));
        }

        let vendor = match parts[0] {
            DEFAULT_VENDOR_BASE => None,
            other => Some(other.to_string()),
        };
        let id = parts[1].to_string();

        Ok(PolicyLocation { vendor, id })
    }
}

impl FromStr for PolicyLocation {
    type Err = ResourceError;

    fn from_str(s: &str) -> Result<Self> {
        TryFrom::try_from(s.to_string())
    }
}

/// Manage the policy files and evaluate the legality of resource
#[async_trait]
pub(crate) trait PolicyEngine: Send + Sync {
    /// Given the resource location and claims, read the resource content from the storage and evaluate the resource according to the claims.
    async fn evaluate(
        &self,
        _resource: ResourceLocation,
        _claims: &str,
        _policy: Vec<PolicyLocation>,
    ) -> Result<bool>;
    /// Create a policy file and write the content inside the file. If it already exists, override it.
    async fn add_policy(&self, _path: PolicyLocation, _policy: &str) -> Result<()>;
    /// Read the policy content from the file.
    async fn get_policy(&self, _path: PolicyLocation) -> Result<String>;
    /// Delete the policy file.
    async fn delete_policy(&self, _path: PolicyLocation) -> Result<()>;
    /// Get all existing policy files.
    async fn get_all_policy(&self) -> Result<Vec<PolicyLocation>>;
    /// Get all policy files of a vendor.
    async fn get_all_policy_in_vendor(&self, _vendor: &str) -> Result<Vec<PolicyLocation>>;
    /// Clear all policy files.
    async fn clear_all_policy(&self) -> Result<()>;
    /// Clear all policy files in vendor.
    async fn clear_all_policy_in_vendor(&self, _vendor: &str) -> Result<()>;
}
