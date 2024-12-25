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

use crate::{error::Result, resource::Resource};
use async_trait::async_trait;

#[async_trait]
pub trait ResourceAdminInterface: Send + Sync {
    /// Get resource from the storage
    async fn get_resource(&self, location: &str) -> Result<Resource>;
    /// Write the content inside the resource in the storage.
    async fn set_resource(
        &self,
        _location: &str,
        _content: String,
        policy: Vec<String>,
    ) -> Result<()>;
    /// Evaluate resource according the claims
    async fn evaluate_resource(&self, location: &str, claim: &str) -> Result<bool>;
}
