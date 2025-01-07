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

use crate::error::{ResourceError, Result};
use crate::policy::PolicyLocation;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, path::PathBuf, str::FromStr};

/// This struct indicates unique resource location under specific base directory.
/// Base directory should be maintained by the resource management engine.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ResourceLocation {
    pub vendor: Option<String>,
    pub path: String,
}

impl std::convert::From<ResourceLocation> for String {
    fn from(value: ResourceLocation) -> Self {
        format!("{}", value)
    }
}

impl std::convert::TryFrom<ResourceLocation> for PathBuf {
    type Error = ResourceError;

    fn try_from(value: ResourceLocation) -> std::result::Result<PathBuf, Self::Error> {
        let path: String = value.into();
        Ok(PathBuf::from_str(&path)?)
    }
}

impl Display for ResourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.vendor.clone().unwrap_or("default".to_string()),
            self.path,
        )
    }
}

impl ResourceLocation {
    pub fn new(vendor: Option<String>, path: String) -> Self {
        Self { vendor, path }
    }

    /// If the vendor if resource or vendor is None, it means using the 'default' vendor.
    ///
    /// If the vendor of policy is 'default', the check always succeed.
    /// Otherwise the vendor of policy should be the same with resource.
    ///
    pub fn check_policy_legal(&self, policy: &PolicyLocation) -> bool {
        let policy_vendor = if policy.vendor.is_none() {
            return true;
        } else {
            policy.vendor.clone().unwrap()
        };

        if policy_vendor.as_str() == "default" {
            return true;
        }

        match self.vendor.as_ref() {
            None => false,
            Some(v) => v == &policy_vendor,
        }
    }
}

/// Policy should be expressed like 'vendor/xxx.rego'
#[derive(Deserialize, Serialize, Debug)]
pub struct Resource {
    pub(crate) content: String,
    pub(crate) policy: Vec<String>,
}

impl Resource {
    pub(crate) fn new(content: String, policy: Vec<PolicyLocation>) -> Self {
        let mut r = Self {
            content,
            policy: vec![],
        };
        r.set_policy(policy);
        r
    }

    pub fn get_content(&self) -> String {
        self.content.clone()
    }

    /// The illegal policy will be ignored and throw warning message.
    pub fn get_policy(&self) -> Vec<PolicyLocation> {
        let mut ret: Vec<PolicyLocation> = vec![];
        for s in self.policy.iter() {
            let p = PolicyLocation::try_from(s.clone());
            match p {
                Ok(p) => ret.push(p),
                Err(_) => {
                    log::warn!("Illegal policy: {}", s);
                }
            }
        }
        ret
    }

    pub fn set_policy(&mut self, policy: Vec<PolicyLocation>) {
        let policy = policy.iter().map(|p| format!("{}", p)).collect();
        self.policy = policy;
    }

    pub(crate) async fn read_from_file(path: PathBuf) -> Result<Self> {
        let content = tokio::fs::read(path)
            .await
            .context("failed to add resource")?;
        Ok(serde_json::from_str(
            &String::from_utf8(content).context("from utf8 error")?,
        )?)
    }

    pub(crate) fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}
