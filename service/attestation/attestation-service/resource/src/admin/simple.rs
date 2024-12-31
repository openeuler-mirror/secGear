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
use crate::error::{ResourceError, Result};
use crate::policy::opa::OpenPolicyAgent;
use crate::policy::PolicyEngine;
use crate::storage::simple::SimpleStorage;
use crate::storage::StorageEngine;
use anyhow::Context;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::Resource;

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
    async fn get_resource(&self, location: &str) -> Result<Resource> {
        self.storage_engine.lock().await.get(location).await
    }

    async fn evaluate_resource(&self, location: &str, claims: &str) -> Result<bool> {
        let resource = self
            .get_resource(location)
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
    async fn set_resource(
        &self,
        _location: &str,
        _content: String,
        _policy: Vec<String>,
    ) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
}
