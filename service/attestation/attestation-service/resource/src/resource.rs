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

use crate::error::Result;
use anyhow::Context;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Deserialize, Serialize, Debug)]
pub struct Resource {
    pub(crate) content: String,
    pub(crate) policy: Vec<String>,
}

impl Resource {
    pub(crate) fn new(content: String, policy: Vec<String>) -> Self {
        Self { content, policy }
    }

    pub fn get_content(&self) -> String {
        self.content.clone()
    }

    pub fn get_policy(&self) -> Vec<String> {
        self.policy.clone()
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
