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
use async_trait::async_trait;

#[async_trait]
pub trait ResourcePolicyEngine: Send + Sync {
    async fn evaluate(&self, _resource: &str, _claim: &str) -> Result<bool> {
        Err(ResourceError::NotImplemented)
    }
    async fn set_policy(&self, _policy: &str) -> Result<()> {
        Err(ResourceError::NotImplemented)
    }
    async fn get_policy(&self, _policy: &str) -> Result<String> {
        Err(ResourceError::NotImplemented)
    }
}
